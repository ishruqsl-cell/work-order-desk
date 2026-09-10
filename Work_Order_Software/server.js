require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_TTL_SECONDS = Number(
  process.env.SESSION_TTL_SECONDS || 8 * 60 * 60
);

if (!process.env.DATABASE_URL) {
  console.error(
    'DATABASE_URL is required. Set it in your hosting provider.'
  );
  process.exit(1);
}

if (
  !process.env.SESSION_SECRET ||
  process.env.SESSION_SECRET.length < 32
) {
  console.error(
    'SESSION_SECRET is required and should be at least 32 characters long.'
  );
  process.exit(1);
}

if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
  console.error(
    'ADMIN_USERNAME and ADMIN_PASSWORD are required for the first admin account.'
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD
    ? { rejectUnauthorized: false }
    : false,
  max: 5,
});

const now = () => new Date().toISOString();

function cleanSupplierCompany(value) {
  return String(value || '')
    .trim()
    .slice(0, 200);
}

function cleanSupplierField(value) {
  return String(value || '')
    .trim()
    .slice(0, 1000);
}

function supplierKey(value) {
  return cleanSupplierCompany(value).toLowerCase();
}

function cleanUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '')
    .slice(0, 64);
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString('hex')
) {
  const hash = crypto
    .scryptSync(String(password), salt, 64)
    .toString('hex');

  return {
    salt,
    hash,
  };
}

function verifyPassword(
  password,
  salt,
  storedHash
) {
  try {
    const derived = Buffer.from(
      hashPassword(password, salt).hash,
      'hex'
    );

    const stored = Buffer.from(
      storedHash,
      'hex'
    );

    return (
      derived.length === stored.length &&
      crypto.timingSafeEqual(
        derived,
        stored
      )
    );
  } catch {
    return false;
  }
}

function sign(value) {
  return crypto
    .createHmac(
      'sha256',
      process.env.SESSION_SECRET
    )
    .update(value)
    .digest('base64url');
}

function makeSession(user) {
  const payload = Buffer.from(
    JSON.stringify({
      userId: user.user_id,
      role: user.role,
      exp:
        Math.floor(Date.now() / 1000) +
        SESSION_TTL_SECONDS,
    })
  ).toString('base64url');

  return `${payload}.${sign(payload)}`;
}

function parseSession(token) {
  if (
    !token ||
    typeof token !== 'string'
  ) {
    return null;
  }

  const [
    payload,
    signature,
  ] = token.split('.');

  if (!payload || !signature) {
    return null;
  }

  const expected = sign(payload);

  try {
    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const data = JSON.parse(
      Buffer.from(
        payload,
        'base64url'
      ).toString('utf8')
    );

    if (
      !data.userId ||
      !data.exp ||
      data.exp <
        Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function setSessionCookie(
  res,
  token
) {
  const parts = [
    `wo_session=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${SESSION_TTL_SECONDS}`,
    'HttpOnly',
    'SameSite=Strict',
  ];

  if (IS_PROD) {
    parts.push('Secure');
  }

  res.setHeader(
    'Set-Cookie',
    parts.join('; ')
  );
}

function clearSessionCookie(res) {
  const parts = [
    'wo_session=',
    'Path=/',
    'Max-Age=0',
    'HttpOnly',
    'SameSite=Strict',
  ];

  if (IS_PROD) {
    parts.push('Secure');
  }

  res.setHeader(
    'Set-Cookie',
    parts.join('; ')
  );
}

async function loadUserFromRequest(req) {
  const cookies = String(
    req.headers.cookie || ''
  )
    .split(';')
    .map(x => x.trim());

  const item = cookies.find(
    x => x.startsWith('wo_session=')
  );

  const token = item
    ? decodeURIComponent(
        item.slice(
          'wo_session='.length
        )
      )
    : '';

  const session =
    parseSession(token);

  if (!session) {
    return null;
  }

  const { rows } =
    await pool.query(
      `
        SELECT
          user_id,
          username,
          role,
          active
        FROM users
        WHERE user_id=$1
      `,
      [session.userId]
    );

  const user = rows[0];

  if (
    !user ||
    !user.active
  ) {
    return null;
  }

  return user;
}

async function optionalAuth(
  req,
  res,
  next
) {
  try {
    req.user =
      await loadUserFromRequest(req);

    next();
  } catch (e) {
    next(e);
  }
}

function requireLogin(
  req,
  res,
  next
) {
  if (!req.user) {
    return res
      .status(401)
      .json({
        error:
          'Editor login required.',
      });
  }

  next();
}

function requireEditor(
  req,
  res,
  next
) {
  if (
    !req.user ||
    ![
      'editor',
      'admin',
    ].includes(req.user.role)
  ) {
    return res
      .status(403)
      .json({
        error:
          'Editor access required.',
      });
  }

  next();
}

function requireAdmin(
  req,
  res,
  next
) {
  if (
    !req.user ||
    req.user.role !== 'admin'
  ) {
    return res
      .status(403)
      .json({
        error:
          'Admin access required.',
      });
  }

  next();
}

async function audit(
  userId,
  action,
  entityType,
  entityId,
  details
) {
  await pool.query(
    `
      INSERT INTO audit_log
      (
        user_id,
        action,
        entity_type,
        entity_id,
        details_json,
        created_at
      )
      VALUES($1,$2,$3,$4,$5,$6)
    `,
    [
      userId || null,
      action,
      entityType,
      entityId == null
        ? null
        : String(entityId),
      details || {},
      now(),
    ]
  );
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY,
      data_json JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      updated_by TEXT
    );

    CREATE TABLE IF NOT EXISTS work_orders (
      id BIGSERIAL PRIMARY KEY,
      work_key TEXT NOT NULL UNIQUE,
      company TEXT NOT NULL,
      wo_number TEXT NOT NULL,
      data_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      archived_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT
    );

    CREATE TABLE IF NOT EXISTS work_order_versions (
      id BIGSERIAL PRIMARY KEY,
      work_order_id BIGINT NOT NULL
        REFERENCES work_orders(id)
        ON DELETE CASCADE,
      version_no INTEGER NOT NULL,
      data_json JSONB NOT NULL,
      saved_at TIMESTAMPTZ NOT NULL,
      saved_by TEXT,
      UNIQUE(
        work_order_id,
        version_no
      )
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      details_json JSONB,
      created_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      role TEXT NOT NULL
        CHECK(
          role IN ('admin','editor')
        ),
      active BOOLEAN NOT NULL
        DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS
      idx_work_orders_updated
      ON work_orders(updated_at DESC);

    CREATE INDEX IF NOT EXISTS
      idx_versions_order
      ON work_order_versions(
        work_order_id,
        version_no DESC
      );

    CREATE INDEX IF NOT EXISTS
      idx_audit_created
      ON audit_log(created_at DESC);

    CREATE INDEX IF NOT EXISTS
      idx_users_username
      ON users(username);

    CREATE TABLE IF NOT EXISTS supplier_profiles (
      id BIGSERIAL PRIMARY KEY,
      company_key TEXT NOT NULL UNIQUE,
      company TEXT NOT NULL,
      contact_name TEXT NOT NULL
        DEFAULT '',
      office_address TEXT NOT NULL
        DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      updated_by TEXT
    );

    CREATE INDEX IF NOT EXISTS
      idx_supplier_profiles_company_key
      ON supplier_profiles(company_key);

    CREATE INDEX IF NOT EXISTS
      idx_supplier_profiles_company
      ON supplier_profiles(company);
  `);

  await pool.query(`
    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      company_key TEXT;

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      company TEXT NOT NULL DEFAULT '';

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      contact_name TEXT NOT NULL DEFAULT '';

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      office_address TEXT NOT NULL DEFAULT '';

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      created_at TIMESTAMPTZ;

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      updated_at TIMESTAMPTZ;

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS
      updated_by TEXT;
  `);

  await pool.query(`
    UPDATE supplier_profiles
    SET company_key =
      LOWER(TRIM(company))
    WHERE company_key IS NULL
       OR company_key = '';
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      uq_supplier_profiles_company_key
      ON supplier_profiles(company_key);
  `);

  const adminUsername =
    cleanUsername(
      process.env.ADMIN_USERNAME
    );

  if (
    !adminUsername ||
    adminUsername.length < 3
  ) {
    throw new Error(
      'ADMIN_USERNAME must contain at least 3 valid characters.'
    );
  }

  const { rows } =
    await pool.query(
      `
        SELECT user_id
        FROM users
        WHERE username=$1
      `,
      [adminUsername]
    );

  if (!rows[0]) {
    const {
      salt,
      hash,
    } = hashPassword(
      process.env.ADMIN_PASSWORD
    );

    const userId =
      `usr_${crypto.randomBytes(10).toString('hex')}`;

    const stamp = now();

    await pool.query(
      `
        INSERT INTO users
        (
          user_id,
          username,
          password_hash,
          password_salt,
          role,
          active,
          created_at,
          updated_at
        )
        VALUES(
          $1,$2,$3,$4,
          'admin',
          TRUE,
          $5,$5
        )
      `,
      [
        userId,
        adminUsername,
        hash,
        salt,
        stamp,
      ]
    );

    console.log(
      `Initial admin account created: ${adminUsername}`
    );
  }
}

app.use(
  express.json({
    limit: '2mb',
  })
);

app.use(optionalAuth);

// ---------------- Authentication ----------------

const failedLogins =
  new Map();

function loginAllowed(ip) {
  const x =
    failedLogins.get(ip);

  if (!x) {
    return true;
  }

  if (
    Date.now() - x.first >
    15 * 60 * 1000
  ) {
    failedLogins.delete(ip);
    return true;
  }

  return x.count < 10;
}

function recordFailedLogin(ip) {
  const x =
    failedLogins.get(ip);

  if (
    !x ||
    Date.now() - x.first >
      15 * 60 * 1000
  ) {
    failedLogins.set(
      ip,
      {
        first: Date.now(),
        count: 1,
      }
    );
  } else {
    x.count += 1;
  }
}

function clearFailedLogin(ip) {
  failedLogins.delete(ip);
}

app.post(
  '/api/login',
  async (req, res) => {
    try {
      const ip =
        req.ip ||
        req.socket.remoteAddress ||
        'unknown';

      if (!loginAllowed(ip)) {
        return res
          .status(429)
          .json({
            error:
              'Too many failed login attempts. Please try again later.',
          });
      }

      const username =
        cleanUsername(
          req.body &&
          req.body.username
        );

      const password =
        String(
          (req.body &&
            req.body.password) ||
          ''
        );

      if (
        !username ||
        !password
      ) {
        return res
          .status(400)
          .json({
            error:
              'Username and password are required.',
          });
      }

      const { rows } =
        await pool.query(
          `
            SELECT
              user_id,
              username,
              password_hash,
              password_salt,
              role,
              active
            FROM users
            WHERE username=$1
          `,
          [username]
        );

      const user = rows[0];

      if (
        !user ||
        !user.active ||
        !verifyPassword(
          password,
          user.password_salt,
          user.password_hash
        )
      ) {
        recordFailedLogin(ip);

        return res
          .status(401)
          .json({
            error:
              'Invalid username or password.',
          });
      }

      clearFailedLogin(ip);

      setSessionCookie(
        res,
        makeSession(user)
      );

      await audit(
        user.user_id,
        'LOGIN',
        'user',
        user.user_id,
        {
          username:
            user.username,
        }
      );

      res.json({
        user: {
          userId:
            user.user_id,
          username:
            user.username,
          role:
            user.role,
        },
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.post(
  '/api/logout',
  async (req, res) => {
    try {
      if (req.user) {
        await audit(
          req.user.user_id,
          'LOGOUT',
          'user',
          req.user.user_id,
          {}
        );
      }
    } catch (_) {}

    clearSessionCookie(res);

    res.json({
      ok: true,
    });
  }
);

app.get(
  '/api/me',
  (req, res) => {
    res.json({
      user: req.user
        ? {
            userId:
              req.user.user_id,
            username:
              req.user.username,
            role:
              req.user.role,
          }
        : null,

      permissions: {
        canEdit:
          !!req.user &&
          [
            'editor',
            'admin',
          ].includes(
            req.user.role
          ),

        canManageUsers:
          !!req.user &&
          req.user.role ===
            'admin',
      },
    });
  }
);

// ---------------- Admin user management ----------------

app.get(
  '/api/users',
  requireAdmin,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
            SELECT
              user_id,
              username,
              role,
              active,
              created_at,
              updated_at
            FROM users
            ORDER BY username
          `
        );

      res.json({
        users: rows,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.post(
  '/api/users',
  requireAdmin,
  async (req, res) => {
    try {
      const username =
        cleanUsername(
          req.body &&
          req.body.username
        );

      const password =
        String(
          (req.body &&
            req.body.password) ||
          ''
        );

      if (
        username.length < 3
      ) {
        return res
          .status(400)
          .json({
            error:
              'Username must be at least 3 characters.',
          });
      }

      if (
        password.length < 8
      ) {
        return res
          .status(400)
          .json({
            error:
              'Password must be at least 8 characters.',
          });
      }

      if (
        username ===
        cleanUsername(
          process.env.ADMIN_USERNAME
        )
      ) {
        return res
          .status(400)
          .json({
            error:
              'This username is reserved for the initial admin account.',
          });
      }

      const {
        salt,
        hash,
      } =
        hashPassword(password);

      const userId =
        `usr_${crypto.randomBytes(10).toString('hex')}`;

      const stamp = now();

      await pool.query(
        `
          INSERT INTO users
          (
            user_id,
            username,
            password_hash,
            password_salt,
            role,
            active,
            created_at,
            updated_at
          )
          VALUES(
            $1,$2,$3,$4,
            'editor',
            TRUE,
            $5,$5
          )
        `,
        [
          userId,
          username,
          hash,
          salt,
          stamp,
        ]
      );

      await audit(
        req.user.user_id,
        'CREATE',
        'user',
        userId,
        {
          username,
          role: 'editor',
        }
      );

      res.json({
        ok: true,
        user: {
          userId,
          username,
          role: 'editor',
          active: true,
        },
      });
    } catch (e) {
      if (
        e.code === '23505'
      ) {
        return res
          .status(409)
          .json({
            error:
              'Username already exists.',
          });
      }

      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.put(
  '/api/users/:userId/password',
  requireAdmin,
  async (req, res) => {
    try {
      const password =
        String(
          (req.body &&
            req.body.password) ||
          ''
        );

      if (
        password.length < 8
      ) {
        return res
          .status(400)
          .json({
            error:
              'Password must be at least 8 characters.',
          });
      }

      const {
        salt,
        hash,
      } =
        hashPassword(password);

      const stamp = now();

      const r =
        await pool.query(
          `
            UPDATE users
            SET
              password_hash=$1,
              password_salt=$2,
              updated_at=$3
            WHERE user_id=$4
            RETURNING username
          `,
          [
            hash,
            salt,
            stamp,
            req.params.userId,
          ]
        );

      if (!r.rows[0]) {
        return res
          .status(404)
          .json({
            error:
              'User not found.',
          });
      }

      await audit(
        req.user.user_id,
        'PASSWORD_RESET',
        'user',
        req.params.userId,
        {
          username:
            r.rows[0].username,
        }
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.put(
  '/api/users/:userId/active',
  requireAdmin,
  async (req, res) => {
    try {
      const active =
        !!(
          req.body &&
          req.body.active
        );

      if (
        req.params.userId ===
          req.user.user_id &&
        !active
      ) {
        return res
          .status(400)
          .json({
            error:
              'You cannot disable your own admin account.',
          });
      }

      if (!active) {
        const target =
          (
            await pool.query(
              `
                SELECT role
                FROM users
                WHERE user_id=$1
              `,
              [req.params.userId]
            )
          ).rows[0];

        if (!target) {
          return res
            .status(404)
            .json({
              error:
                'User not found.',
            });
        }

        if (
          target.role ===
          'admin'
        ) {
          const n =
            Number(
              (
                await pool.query(
                  `
                    SELECT COUNT(*) AS n
                    FROM users
                    WHERE role='admin'
                      AND active=TRUE
                  `
                )
              ).rows[0].n
            );

          if (n <= 1) {
            return res
              .status(400)
              .json({
                error:
                  'At least one active admin must remain.',
              });
          }
        }
      }

      const stamp = now();

      const r =
        await pool.query(
          `
            UPDATE users
            SET
              active=$1,
              updated_at=$2
            WHERE user_id=$3
            RETURNING
              username,
              role,
              active
          `,
          [
            active,
            stamp,
            req.params.userId,
          ]
        );

      if (!r.rows[0]) {
        return res
          .status(404)
          .json({
            error:
              'User not found.',
          });
      }

      await audit(
        req.user.user_id,
        active
          ? 'ENABLE'
          : 'DISABLE',
        'user',
        req.params.userId,
        {
          username:
            r.rows[0].username,
        }
      );

      res.json({
        ok: true,
        user: {
          userId:
            req.params.userId,
          ...r.rows[0],
        },
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

// ---------------- Supplier / factory memory ----------------

app.get(
  '/api/suppliers',
  async (req, res) => {
    try {
      const search =
        cleanSupplierCompany(
          req.query &&
          req.query.search
        );

      const limit =
        Math.min(
          50,
          Math.max(
            1,
            Number(
              req.query &&
              req.query.limit
            ) || 20
          )
        );

      const params = [];
      let profileWhere = '';

      if (search) {
        params.push(
          `%${supplierKey(search)}%`
        );

        profileWhere =
          'WHERE company_key LIKE $1';
      }

      const profileRows =
        (
          await pool.query(
            `
              SELECT
                company,
                contact_name,
                office_address,
                updated_at
              FROM supplier_profiles
              ${profileWhere}
              ORDER BY company
              LIMIT ${limit}
            `,
            params
          )
        ).rows;

      // Search ALL Work Orders,
      // including archived Work Orders.
      const orderParams =
        search
          ? [
              `%${supplierKey(search)}%`,
            ]
          : [];

      const orderWhere =
        search
          ? `
              WHERE LOWER(
                COALESCE(
                  data_json->>'supplierCompany',
                  ''
                )
              ) LIKE $1
            `
          : `
              WHERE COALESCE(
                data_json->>'supplierCompany',
                ''
              ) <> ''
            `;

      const orderRows =
        (
          await pool.query(
            `
              SELECT
                data_json,
                updated_at
              FROM work_orders
              ${orderWhere}
              ORDER BY updated_at DESC
              LIMIT 500
            `,
            orderParams
          )
        ).rows;

      const map =
        new Map();

      // Supplier profiles have priority.
      for (
        const row of profileRows
      ) {
        const company =
          cleanSupplierCompany(
            row.company
          );

        if (!company) {
          continue;
        }

        map.set(
          supplierKey(company),
          {
            company,
            contact:
              cleanSupplierField(
                row.contact_name
              ),
            address:
              cleanSupplierField(
                row.office_address
              ),
            updatedAt:
              row.updated_at,
          }
        );
      }

      // Fill missing companies
      // from historical Work Orders.
      for (
        const row of orderRows
      ) {
        const d =
          row.data_json || {};

        const company =
          cleanSupplierCompany(
            d.supplierCompany
          );

        if (!company) {
          continue;
        }

        const key =
          supplierKey(company);

        if (!map.has(key)) {
          map.set(
            key,
            {
              company,
              contact:
                cleanSupplierField(
                  d.supplierContact
                ),
              address:
                cleanSupplierField(
                  d.supplierAddress
                ),
              updatedAt:
                row.updated_at,
            }
          );
        }
      }

      res.json({
        suppliers:
          Array.from(
            map.values()
          )
            .sort(
              (a, b) =>
                a.company.localeCompare(
                  b.company
                )
            )
            .slice(0, limit),
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.get(
  '/api/suppliers/by-company',
  async (req, res) => {
    try {
      const company =
        cleanSupplierCompany(
          req.query &&
          req.query.company
        );

      if (!company) {
        return res.json({
          supplier: null,
        });
      }

      const key =
        supplierKey(company);

      const profile =
        (
          await pool.query(
            `
              SELECT
                company,
                contact_name,
                office_address,
                updated_at
              FROM supplier_profiles
              WHERE company_key=$1
              LIMIT 1
            `,
            [key]
          )
        ).rows[0];

      if (profile) {
        return res.json({
          supplier: {
            company:
              profile.company,

            contact:
              cleanSupplierField(
                profile.contact_name
              ),

            address:
              cleanSupplierField(
                profile.office_address
              ),

            updatedAt:
              profile.updated_at,
          },
        });
      }

      // Fallback to newest
      // matching Work Order,
      // including archived orders.
      const row =
        (
          await pool.query(
            `
              SELECT
                data_json,
                updated_at
              FROM work_orders
              WHERE LOWER(
                COALESCE(
                  data_json->>'supplierCompany',
                  ''
                )
              )=$1
              ORDER BY updated_at DESC
              LIMIT 1
            `,
            [key]
          )
        ).rows[0];

      if (!row) {
        return res.json({
          supplier: null,
        });
      }

      const d =
        row.data_json || {};

      res.json({
        supplier: {
          company:
            cleanSupplierCompany(
              d.supplierCompany
            ),

          contact:
            cleanSupplierField(
              d.supplierContact
            ),

          address:
            cleanSupplierField(
              d.supplierAddress
            ),

          updatedAt:
            row.updated_at,
        },
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

// ---------------- Public viewer endpoints ----------------

app.get(
  '/api/settings',
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
            SELECT data_json
            FROM settings
            WHERE id=1
          `
        );

      res.json({
        settings:
          rows[0]
            ? rows[0].data_json
            : null,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.get(
  '/api/work-orders',
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
            SELECT
              id,
              work_key,
              company,
              wo_number,
              data_json,
              created_at,
              updated_at,
              archived_at
            FROM work_orders
            ORDER BY updated_at DESC
          `
        );

      const index =
        rows
          .filter(
            r => !r.archived_at
          )
          .map(r => {
            const d =
              r.data_json || {};

            const items =
              Array.isArray(
                d.items
              )
                ? d.items
                : [];

            return {
              key:
                r.work_key,

              company:
                r.company,

              woNumber:
                r.wo_number,

              date:
                d.date || '',

              supplierCompany:
                d.supplierCompany ||
                '',

              total:
                items.reduce(
                  (
                    sum,
                    it
                  ) =>
                    sum +
                    (Number(
                      it.qty
                    ) || 0) *
                    (Number(
                      it.unitPrice
                    ) || 0),
                  0
                ),

              savedAt:
                r.updated_at,

              items:
                items
                  .filter(
                    it => it.style
                  )
                  .map(
                    it => ({
                      style:
                        it.style,

                      qty:
                        it.qty,

                      unitPrice:
                        it.unitPrice,
                    })
                  ),
            };
          });

      res.json({
        index,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.get(
  '/api/work-orders/:key',
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
            SELECT *
            FROM work_orders
            WHERE work_key=$1
              AND archived_at IS NULL
          `,
          [req.params.key]
        );

      if (!rows[0]) {
        return res
          .status(404)
          .json({
            error:
              'Work order not found',
          });
      }

      const r = rows[0];

      res.json({
        order:
          r.data_json,

        meta: {
          id:
            r.id,

          createdAt:
            r.created_at,

          updatedAt:
            r.updated_at,

          archivedAt:
            r.archived_at,
        },
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.get(
  '/api/work-orders/:key/versions',
  requireLogin,
  async (req, res) => {
    try {
      const r =
        (
          await pool.query(
            `
              SELECT id
              FROM work_orders
              WHERE work_key=$1
            `,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res
          .status(404)
          .json({
            error:
              'Work order not found',
          });
      }

      const { rows } =
        await pool.query(
          `
            SELECT
              id,
              version_no,
              saved_at,
              saved_by
            FROM work_order_versions
            WHERE work_order_id=$1
            ORDER BY version_no DESC
          `,
          [r.id]
        );

      res.json({
        versions: rows,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

app.get(
  '/api/work-orders/:key/versions/:version',
  requireLogin,
  async (req, res) => {
    try {
      const r =
        (
          await pool.query(
            `
              SELECT id
              FROM work_orders
              WHERE work_key=$1
            `,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res
          .status(404)
          .json({
            error:
              'Work order not found',
          });
      }

      const v =
        (
          await pool.query(
            `
              SELECT *
              FROM work_order_versions
              WHERE work_order_id=$1
                AND version_no=$2
            `,
            [
              r.id,
              Number(
                req.params.version
              ),
            ]
          )
        ).rows[0];

      if (!v) {
        return res
          .status(404)
          .json({
            error:
              'Version not found',
          });
      }

      res.json({
        order:
          v.data_json,

        version:
          v.version_no,

        savedAt:
          v.saved_at,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

// ---------------- Editor/Admin write endpoints ----------------

app.put(
  '/api/settings',
  requireEditor,
  async (req, res) => {
    const data =
      req.body &&
      req.body.settings;

    if (
      !data ||
      typeof data !== 'object'
    ) {
      return res
        .status(400)
        .json({
          error:
            'Invalid settings',
        });
    }

    try {
      await pool.query(
        `
          INSERT INTO settings
          (
            id,
            data_json,
            updated_at,
            updated_by
          )
          VALUES(
            1,
            $1,
            $2,
            $3
          )
          ON CONFLICT(id)
          DO UPDATE SET
            data_json =
              EXCLUDED.data_json,
            updated_at =
              EXCLUDED.updated_at,
            updated_by =
              EXCLUDED.updated_by
        `,
        [
          data,
          now(),
          req.user.user_id,
        ]
      );

      await audit(
        req.user.user_id,
        'UPDATE',
        'settings',
        '1',
        {}
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

async function saveOrder(
  order,
  userId
) {
  const company =
    String(
      order.company || ''
    ).trim();

  const woNumber =
    String(
      order.woNumber || ''
    ).trim();

  if (
    !company ||
    !woNumber
  ) {
    throw new Error(
      'Company and Work Order No are required.'
    );
  }

  const key =
    `wo:${company}::${woNumber}`;

  const client =
    await pool.connect();

  try {
    await client.query(
      'BEGIN'
    );

    const stamp = now();

    // Remember supplier/factory
    // details by company name.
    const supplierCompany =
      cleanSupplierCompany(
        order.supplierCompany
      );

    const supplierContact =
      cleanSupplierField(
        order.supplierContact
      );

    const supplierAddress =
      cleanSupplierField(
        order.supplierAddress
      );

    if (supplierCompany) {
      const sKey =
        supplierKey(
          supplierCompany
        );

      await client.query(
        `
          INSERT INTO supplier_profiles
          (
            company_key,
            company,
            contact_name,
            office_address,
            created_at,
            updated_at,
            updated_by
          )
          VALUES(
            $1,$2,$3,$4,$5,$5,$6
          )
          ON CONFLICT(company_key)
          DO UPDATE SET
            company =
              EXCLUDED.company,

            contact_name =
              EXCLUDED.contact_name,

            office_address =
              EXCLUDED.office_address,

            updated_at =
              EXCLUDED.updated_at,

            updated_by =
              EXCLUDED.updated_by
        `,
        [
          sKey,
          supplierCompany,
          supplierContact,
          supplierAddress,
          stamp,
          userId,
        ]
      );
    }

    const existing =
      (
        await client.query(
          `
            SELECT *
            FROM work_orders
            WHERE work_key=$1
            FOR UPDATE
          `,
          [key]
        )
      ).rows[0];

    let id;

    if (existing) {
      id = existing.id;

      await client.query(
        `
          UPDATE work_orders
          SET
            company=$1,
            wo_number=$2,
            data_json=$3,
            updated_at=$4,
            archived_at=NULL,
            updated_by=$5
          WHERE id=$6
        `,
        [
          company,
          woNumber,
          order,
          stamp,
          userId,
          id,
        ]
      );
    } else {
      const r =
        await client.query(
          `
            INSERT INTO work_orders
            (
              work_key,
              company,
              wo_number,
              data_json,
              created_at,
              updated_at,
              created_by,
              updated_by
            )
            VALUES(
              $1,$2,$3,$4,
              $5,$5,$6,$6
            )
            RETURNING id
          `,
          [
            key,
            company,
            woNumber,
            order,
            stamp,
            userId,
          ]
        );

      id =
        r.rows[0].id;
    }

    const last =
      Number(
        (
          await client.query(
            `
              SELECT
                COALESCE(
                  MAX(version_no),
                  0
                ) AS n
              FROM work_order_versions
              WHERE work_order_id=$1
            `,
            [id]
          )
        ).rows[0].n
      );

    const version =
      last + 1;

    await client.query(
      `
        INSERT INTO work_order_versions
        (
          work_order_id,
          version_no,
          data_json,
          saved_at,
          saved_by
        )
        VALUES(
          $1,$2,$3,$4,$5
        )
      `,
      [
        id,
        version,
        order,
        stamp,
        userId,
      ]
    );

    await client.query(
      `
        INSERT INTO audit_log
        (
          user_id,
          action,
          entity_type,
          entity_id,
          details_json,
          created_at
        )
        VALUES(
          $1,$2,$3,$4,$5,$6
        )
      `,
      [
        userId,
        existing
          ? 'UPDATE'
          : 'CREATE',
        'work_order',
        String(id),
        {
          workKey: key,
          version,
        },
        stamp,
      ]
    );

    await client.query(
      'COMMIT'
    );

    return {
      key,
      id,
      version,
      savedAt: stamp,
    };
  } catch (e) {
    await client.query(
      'ROLLBACK'
    );

    throw e;
  } finally {
    client.release();
  }
}

app.post(
  '/api/work-orders',
  requireEditor,
  async (req, res) => {
    try {
      const order =
        req.body &&
        req.body.order;

      if (!order) {
        return res
          .status(400)
          .json({
            error:
              'Order data is required',
          });
      }

      const result =
        await saveOrder(
          order,
          req.user.user_id
        );

      res.json({
        ok: true,
        ...result,
      });
    } catch (e) {
      res
        .status(400)
        .json({
          error:
            e.message ||
            'Save failed',
        });
    }
  }
);

app.delete(
  '/api/work-orders/:key',
  requireEditor,
  async (req, res) => {
    try {
      const r =
        (
          await pool.query(
            `
              SELECT id
              FROM work_orders
              WHERE work_key=$1
            `,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res
          .status(404)
          .json({
            error:
              'Work order not found',
          });
      }

      const stamp = now();

      await pool.query(
        `
          UPDATE work_orders
          SET
            archived_at=$1,
            updated_at=$1,
            updated_by=$2
          WHERE id=$3
        `,
        [
          stamp,
          req.user.user_id,
          r.id,
        ]
      );

      await audit(
        req.user.user_id,
        'ARCHIVE',
        'work_order',
        r.id,
        {
          workKey:
            req.params.key,
        }
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

// Audit is admin-only.
app.get(
  '/api/audit',
  requireAdmin,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `
            SELECT
              id,
              action,
              entity_type,
              entity_id,
              created_at,
              user_id
            FROM audit_log
            ORDER BY created_at DESC
            LIMIT 500
          `
        );

      res.json({
        audit: rows,
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message,
        });
    }
  }
);

// ---------------- Static app ----------------

app.use(
  express.static(
    path.join(
      ROOT,
      'public'
    )
  )
);

app.get(
  '/{*splat}',
  (req, res) =>
    res.sendFile(
      path.join(
        ROOT,
        'public',
        'app.html'
      )
    )
);

initDb()
  .then(() => {
    app.listen(
      PORT,
      '0.0.0.0',
      () =>
        console.log(
          `Work Order Desk running on port ${PORT}`
        )
    );
  })
  .catch(err => {
    console.error(
      'Database initialization failed:',
      err
    );

    process.exit(1);
  });
