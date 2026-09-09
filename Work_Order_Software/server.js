require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 8 * 60 * 60);

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Set it in your hosting provider.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET is required and should be at least 32 characters long.');
  process.exit(1);
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
  console.error('ADMIN_USERNAME and ADMIN_PASSWORD are required for the first admin account.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
  max: 5,
});

const now = () => new Date().toISOString();
const safeJson = (s) => {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
};

function cleanSupplierCompany(value) {
  return String(value || '').trim().slice(0, 200);
}

function cleanSupplierField(value) {
  return String(value || '').trim().slice(0, 1000);
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

  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  try {
    const derived = Buffer.from(
      hashPassword(password, salt).hash,
      'hex'
    );

    const stored = Buffer.from(storedHash, 'hex');

    return (
      derived.length === stored.length &&
      crypto.timingSafeEqual(derived, stored)
    );
  } catch {
    return false;
  }
}

function sign(value) {
  return crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
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
  if (!token || typeof token !== 'string') return null;

  const [payload, signature] = token.split('.');

  if (!payload || !signature) return null;

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
      Buffer.from(payload, 'base64url').toString('utf8')
    );

    if (
      !data.userId ||
      !data.exp ||
      data.exp < Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function setSessionCookie(res, token) {
  const parts = [
    `wo_session=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${SESSION_TTL_SECONDS}`,
    'HttpOnly',
    'SameSite=Strict',
  ];

  if (IS_PROD) parts.push('Secure');

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

  if (IS_PROD) parts.push('Secure');

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
        item.slice('wo_session='.length)
      )
    : '';

  const session = parseSession(token);

  if (!session) return null;

  const { rows } = await pool.query(
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

  if (!user || !user.active) return null;

  return user;
}

async function optionalAuth(req, res, next) {
  try {
    req.user = await loadUserFromRequest(req);
    next();
  } catch (e) {
    next(e);
  }
}

function requireLogin(req, res, next) {
  if (!req.user) {
    return res
      .status(401)
      .json({
        error: 'Editor login required.'
      });
  }

  next();
}

function requireEditor(req, res, next) {
  if (
    !req.user ||
    !['editor', 'admin'].includes(req.user.role)
  ) {
    return res
      .status(403)
      .json({
        error: 'Editor access required.'
      });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (
    !req.user ||
    req.user.role !== 'admin'
  ) {
    return res
      .status(403)
      .json({
        error: 'Admin access required.'
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
      UNIQUE(work_order_id, version_no)
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
        CHECK(role IN ('admin','editor')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
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
      contact_name TEXT NOT NULL DEFAULT '',
      office_address TEXT NOT NULL DEFAULT '',
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

  // Safe migration for an earlier supplier_profiles version.
  await pool.query(`
    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS company_key TEXT;

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS company
      TEXT NOT NULL DEFAULT '';

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS contact_name
      TEXT NOT NULL DEFAULT '';

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS office_address
      TEXT NOT NULL DEFAULT '';

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS created_at
      TIMESTAMPTZ;

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS updated_at
      TIMESTAMPTZ;

    ALTER TABLE supplier_profiles
      ADD COLUMN IF NOT EXISTS updated_by
      TEXT;
  `);

  await pool.query(`
    UPDATE supplier_profiles
    SET company_key = LOWER(TRIM(company))
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

  const { rows } = await pool.query(
    `
      SELECT user_id
      FROM users
      WHERE username=$1
    `,
    [adminUsername]
  );

  if (!rows[0]) {
    const { salt, hash } =
      hashPassword(
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
    limit: '2mb'
  })
);

app.use(optionalAuth);

// ---------------- Authentication ----------------

const failedLogins = new Map();

function loginAllowed(ip) {
  const x = failedLogins.get(ip);

  if (!x) return true;

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
  const x = failedLogins.get(ip);

  if (
    !x ||
    Date.now() - x.first >
      15 * 60 * 1000
  ) {
    failedLogins.set(
      ip,
      {
        first: Date.now(),
        count: 1
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
              'Too many failed login attempts. Please try again later.'
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

      if (!username || !password) {
        return res
          .status(400)
          .json({
            error:
              'Username and password are required.'
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
              'Invalid username or password.'
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
          username: user.username
        }
      );

      res.json({
        user: {
          userId: user.user_id,
          username: user.username,
          role: user.role
        }
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
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
      ok: true
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
              req.user.role
          }
        : null,

      permissions: {
        canEdit:
          !!req.user &&
          ['editor', 'admin']
            .includes(
              req.user.role
            ),

        canManageUsers:
          !!req.user &&
          req.user.role ===
            'admin'
      }
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
        users: rows
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
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

      if (username.length < 3) {
        return res
          .status(400)
          .json({
            error:
              'Username must be at least 3 characters.'
          });
      }

      if (password.length < 8) {
        return res
          .status(400)
          .json({
            error:
              'Password must be at least 8 characters.'
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
              'This username is reserved for the initial admin account.'
          });
      }

      const {
        salt,
        hash
      } = hashPassword(password);

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
          stamp
        ]
      );

      await audit(
        req.user.user_id,
        'CREATE',
        'user',
        userId,
        {
          username,
          role: 'editor'
        }
      );

      res.json({
        ok: true,
        user: {
          userId,
          username,
          role: 'editor',
          active: true
        }
      });
    } catch (e) {
      if (e.code === '23505') {
        return res
          .status(409)
          .json({
            error:
              'Username already exists.'
          });
      }

      res
        .status(500)
        .json({
          error: e.message
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

      if (password.length < 8) {
        return res
          .status(400)
          .json({
            error:
              'Password must be at least 8 characters.'
          });
      }

      const {
        salt,
        hash
      } = hashPassword(password);

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
            req.params.userId
          ]
        );

      if (!r.rows[0]) {
        return res
          .status(404)
          .json({
            error:
              'User not found.'
          });
      }

      await audit(
        req.user.user_id,
        'PASSWORD_RESET',
        'user',
        req.params.userId,
        {
          username:
            r.rows[0].username
        }
      );

      res.json({
        ok: true
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
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
              'You cannot disable your own admin account.'
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
                'User not found.'
            });
        }

        if (target.role === 'admin') {
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
                  'At least one active admin must remain.'
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
            req.params.userId
          ]
        );

      if (!r.rows[0]) {
        return res
          .status(404)
          .json({
            error:
              'User not found.'
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
            r.rows[0].username
        }
      );

      res.json({
        ok: true,
        user: {
          userId:
            req.params.userId,
          ...r.rows[0]
        }
      });
    } catch (e) {
      res
        .status(500)
        .json({
          error: e.message
        });
    }
  }
);
