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
  console.error('DATABASE_URL is required.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET is required and must be at least 32 characters.');
  process.exit(1);
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
  console.error('ADMIN_USERNAME and ADMIN_PASSWORD are required.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
  max: Number(process.env.DB_POOL_MAX || 10),
});

// Without this handler, a dropped/idle database connection (very common on
// free-tier hosting, where the DB or this server can go to sleep) crashes
// the entire Node process instead of just failing the one request that was
// affected. This is what was causing random 500 errors across different
// buttons/modules and the server needing to restart itself repeatedly.
pool.on('error', (err) => {
  console.error('Unexpected error on idle database client:', err);
});

const now = () => new Date().toISOString();

function text(value, max = 1000) {
  return String(value ?? '').trim().slice(0, max);
}
function cleanUsername(value) {
  return text(value, 64).toLowerCase().replace(/[^a-z0-9._-]/g, '');
}
function cleanCompany(value) {
  return text(value, 200);
}
function companyKey(value) {
  return cleanCompany(value).toLowerCase();
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString('hex')
) {
  return {
    salt,
    hash: crypto.scryptSync(String(password), salt, 64).toString('hex'),
  };
}

function verifyPassword(password, salt, storedHash) {
  try {
    const a = Buffer.from(hashPassword(password, salt).hash, 'hex');
    const b = Buffer.from(storedHash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
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
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
    })
  ).toString('base64url');

  return `${payload}.${sign(payload)}`;
}

function parseSession(token) {
  if (!token || typeof token !== 'string') return null;

  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  try {
    const expected = sign(payload);

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

  res.setHeader('Set-Cookie', parts.join('; '));
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

  res.setHeader('Set-Cookie', parts.join('; '));
}

async function loadUserFromRequest(req) {
  const cookies = String(req.headers.cookie || '')
    .split(';')
    .map(v => v.trim());

  const item = cookies.find(v => v.startsWith('wo_session='));

  const token = item
    ? decodeURIComponent(item.slice('wo_session='.length))
    : '';

  const session = parseSession(token);

  if (!session) return null;

  const { rows } = await pool.query(
    `SELECT user_id, username, role, active
     FROM users
     WHERE user_id=$1`,
    [session.userId]
  );

  const user = rows[0];

  return user && user.active ? user : null;
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
    return res.status(401).json({
      error: 'Login required.',
    });
  }

  next();
}

function requireEditor(req, res, next) {
  if (
    !req.user ||
    !['editor', 'admin'].includes(req.user.role)
  ) {
    return res.status(403).json({
      error: 'Editor access required.',
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Admin access required.',
    });
  }

  next();
}

async function audit(
  userId,
  action,
  entityType,
  entityId,
  details = {}
) {
  await pool.query(
    `INSERT INTO audit_log
      (user_id, action, entity_type, entity_id, details_json, created_at)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [
      userId || null,
      action,
      entityType,
      entityId == null ? null : String(entityId),
      details,
      now(),
    ]
  );
}

const failedLogins = new Map();

function loginAllowed(ip) {
  const x = failedLogins.get(ip);

  if (!x) return true;

  if (Date.now() - x.first > 15 * 60 * 1000) {
    failedLogins.delete(ip);
    return true;
  }

  return x.count < 10;
}

function recordFailedLogin(ip) {
  const x = failedLogins.get(ip);

  if (!x || Date.now() - x.first > 15 * 60 * 1000) {
    failedLogins.set(ip, {
      first: Date.now(),
      count: 1,
    });
  } else {
    x.count += 1;
  }
}

function clearFailedLogin(ip) {
  failedLogins.delete(ip);
}

app.disable('x-powered-by');
app.use(express.json({
  limit: process.env.JSON_LIMIT || '10mb',
}));
app.use(optionalAuth);

/* ---------------- Authentication ---------------- */

app.post('/api/login', async (req, res) => {
  try {
    const ip =
      req.ip ||
      req.socket.remoteAddress ||
      'unknown';

    if (!loginAllowed(ip)) {
      return res.status(429).json({
        error:
          'Too many failed login attempts. Please try again later.',
      });
    }

    const username = cleanUsername(req.body?.username);
    const password = String(req.body?.password || '');

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required.',
      });
    }

    const { rows } = await pool.query(
      `SELECT
         user_id,
         username,
         password_hash,
         password_salt,
         role,
         active
       FROM users
       WHERE username=$1`,
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

      return res.status(401).json({
        error: 'Invalid username or password.',
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
      { username: user.username }
    );

    res.json({
      ok: true,
      user: {
        userId: user.user_id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (e) {
    res.status(500).json({
      error: 'Login failed.',
    });
  }
});

app.post('/api/logout', async (req, res) => {
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

  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({
    user: req.user
      ? {
          userId: req.user.user_id,
          username: req.user.username,
          role: req.user.role,
        }
      : null,

    permissions: {
      canEdit:
        !!req.user &&
        ['editor', 'admin'].includes(req.user.role),

      canManageUsers:
        !!req.user &&
        req.user.role === 'admin',
    },
  });
});

/* ---------------- Database ---------------- */

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
      role TEXT NOT NULL CHECK(role IN ('admin','editor')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );

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

    CREATE TABLE IF NOT EXISTS module_records (
      id BIGSERIAL PRIMARY KEY,
      module TEXT NOT NULL,
      record_key TEXT NOT NULL,
      data_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      archived_at TIMESTAMPTZ,
      created_by TEXT,
      updated_by TEXT,
      UNIQUE(module, record_key)
    );

    CREATE INDEX IF NOT EXISTS idx_work_orders_updated
      ON work_orders(updated_at DESC);

    CREATE INDEX IF NOT EXISTS idx_versions_order
      ON work_order_versions(work_order_id, version_no DESC);

    CREATE INDEX IF NOT EXISTS idx_audit_created
      ON audit_log(created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_users_username
      ON users(username);

    CREATE INDEX IF NOT EXISTS idx_module_records_module
      ON module_records(module, updated_at DESC);

    CREATE INDEX IF NOT EXISTS idx_supplier_company
      ON supplier_profiles(company);
  `);

  const adminUsername =
    cleanUsername(process.env.ADMIN_USERNAME);

  if (adminUsername.length < 3) {
    throw new Error(
      'ADMIN_USERNAME must contain at least 3 valid characters.'
    );
  }

  const found = await pool.query(
    `SELECT user_id
     FROM users
     WHERE username=$1`,
    [adminUsername]
  );

  if (!found.rows[0]) {
    const { salt, hash } =
      hashPassword(process.env.ADMIN_PASSWORD);

    const userId =
      `usr_${crypto.randomBytes(10).toString('hex')}`;

    const stamp = now();

    await pool.query(
      `INSERT INTO users
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
       VALUES
       (
         $1,$2,$3,$4,'admin',TRUE,$5,$5
       )`,
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

/* ---------------- Admin users ---------------- */

app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         user_id,
         username,
         role,
         active,
         created_at,
         updated_at
       FROM users
       ORDER BY username`
    );

    res.json({ users: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', requireAdmin, async (req, res) => {
  try {
    const username =
      cleanUsername(req.body?.username);

    const password =
      String(req.body?.password || '');

    if (username.length < 3) {
      return res.status(400).json({
        error:
          'Username must be at least 3 characters.',
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          'Password must be at least 8 characters.',
      });
    }

    if (
      username ===
      cleanUsername(process.env.ADMIN_USERNAME)
    ) {
      return res.status(400).json({
        error:
          'This username is reserved for the initial admin account.',
      });
    }

    const { salt, hash } =
      hashPassword(password);

    const userId =
      `usr_${crypto.randomBytes(10).toString('hex')}`;

    const stamp = now();

    await pool.query(
      `INSERT INTO users
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
       VALUES
       (
         $1,$2,$3,$4,'editor',TRUE,$5,$5
       )`,
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
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'Username already exists.',
      });
    }

    res.status(500).json({
      error: e.message,
    });
  }
});

app.put(
  '/api/users/:userId/password',
  requireAdmin,
  async (req, res) => {
    try {
      const password =
        String(req.body?.password || '');

      if (password.length < 8) {
        return res.status(400).json({
          error:
            'Password must be at least 8 characters.',
        });
      }

      const { salt, hash } =
        hashPassword(password);

      const stamp = now();

      const r = await pool.query(
        `UPDATE users
         SET
           password_hash=$1,
           password_salt=$2,
           updated_at=$3
         WHERE user_id=$4
         RETURNING username`,
        [
          hash,
          salt,
          stamp,
          req.params.userId,
        ]
      );

      if (!r.rows[0]) {
        return res.status(404).json({
          error: 'User not found.',
        });
      }

      await audit(
        req.user.user_id,
        'PASSWORD_RESET',
        'user',
        req.params.userId,
        {
          username: r.rows[0].username,
        }
      );

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({
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
        !!req.body?.active;

      if (
        req.params.userId ===
          req.user.user_id &&
        !active
      ) {
        return res.status(400).json({
          error:
            'You cannot disable your own admin account.',
        });
      }

      if (!active) {
        const target =
          (
            await pool.query(
              `SELECT role
               FROM users
               WHERE user_id=$1`,
              [req.params.userId]
            )
          ).rows[0];

        if (!target) {
          return res.status(404).json({
            error: 'User not found.',
          });
        }

        if (target.role === 'admin') {
          const n =
            Number(
              (
                await pool.query(
                  `SELECT COUNT(*) AS n
                   FROM users
                   WHERE role='admin'
                   AND active=TRUE`
                )
              ).rows[0].n
            );

          if (n <= 1) {
            return res.status(400).json({
              error:
                'At least one active admin must remain.',
            });
          }
        }
      }

      const r = await pool.query(
        `UPDATE users
         SET
           active=$1,
           updated_at=$2
         WHERE user_id=$3
         RETURNING
           user_id,
           username,
           role,
           active`,
        [
          active,
          now(),
          req.params.userId,
        ]
      );

      if (!r.rows[0]) {
        return res.status(404).json({
          error: 'User not found.',
        });
      }

      await audit(
        req.user.user_id,
        active ? 'ENABLE' : 'DISABLE',
        'user',
        req.params.userId,
        {
          username:
            r.rows[0].username,
        }
      );

      res.json({
        ok: true,
        user: r.rows[0],
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- Suppliers ---------------- */

app.get('/api/suppliers', async (req, res) => {
  try {
    const search =
      cleanCompany(req.query?.search);

    const limit =
      Math.min(
        100,
        Math.max(
          1,
          Number(req.query?.limit) || 50
        )
      );

    const profiles =
      await pool.query(
        search
          ? `SELECT
               company,
               contact_name,
               office_address,
               updated_at
             FROM supplier_profiles
             WHERE company_key LIKE $1
             ORDER BY company
             LIMIT $2`
          : `SELECT
               company,
               contact_name,
               office_address,
               updated_at
             FROM supplier_profiles
             ORDER BY company
             LIMIT $1`,
        search
          ? [
              `%${companyKey(search)}%`,
              limit,
            ]
          : [limit]
      );

    const map = new Map();

    for (const r of profiles.rows) {
      map.set(
        companyKey(r.company),
        {
          company: r.company,
          contact: r.contact_name,
          address: r.office_address,
          updatedAt: r.updated_at,
        }
      );
    }

    const orders =
      await pool.query(
        search
          ? `SELECT
               data_json,
               updated_at
             FROM work_orders
             WHERE LOWER(
               COALESCE(
                 data_json->>'supplierCompany',
                 ''
               )
             ) LIKE $1
             ORDER BY updated_at DESC
             LIMIT 500`
          : `SELECT
               data_json,
               updated_at
             FROM work_orders
             WHERE COALESCE(
               data_json->>'supplierCompany',
               ''
             ) <> ''
             ORDER BY updated_at DESC
             LIMIT 500`,
        search
          ? [`%${companyKey(search)}%`]
          : []
      );

    for (const r of orders.rows) {
      const d = r.data_json || {};

      const company =
        cleanCompany(d.supplierCompany);

      if (!company) continue;

      const key =
        companyKey(company);

      if (!map.has(key)) {
        map.set(key, {
          company,
          contact:
            text(d.supplierContact),
          address:
            text(d.supplierAddress),
          updatedAt:
            r.updated_at,
        });
      }
    }

    res.json({
      suppliers: [
        ...map.values(),
      ]
        .sort((a, b) =>
          a.company.localeCompare(b.company)
        )
        .slice(0, limit),
    });
  } catch (e) {
    res.status(500).json({
      error: e.message,
    });
  }
});

app.get(
  '/api/suppliers/by-company',
  async (req, res) => {
    try {
      const company =
        cleanCompany(req.query?.company);

      if (!company) {
        return res.json({
          supplier: null,
        });
      }

      const key =
        companyKey(company);

      const profile =
        (
          await pool.query(
            `SELECT
               company,
               contact_name,
               office_address,
               updated_at
             FROM supplier_profiles
             WHERE company_key=$1
             LIMIT 1`,
            [key]
          )
        ).rows[0];

      if (profile) {
        return res.json({
          supplier: {
            company: profile.company,
            contact: profile.contact_name,
            address: profile.office_address,
            updatedAt: profile.updated_at,
          },
        });
      }

      const r =
        (
          await pool.query(
            `SELECT
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
             LIMIT 1`,
            [key]
          )
        ).rows[0];

      if (!r) {
        return res.json({
          supplier: null,
        });
      }

      const d = r.data_json || {};

      res.json({
        supplier: {
          company:
            cleanCompany(d.supplierCompany),
          contact:
            text(d.supplierContact),
          address:
            text(d.supplierAddress),
          updatedAt:
            r.updated_at,
        },
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.put(
  '/api/suppliers',
  requireEditor,
  async (req, res) => {
    try {
      const company =
        cleanCompany(req.body?.company);

      if (!company) {
        return res.status(400).json({
          error:
            'Supplier company is required.',
        });
      }

      const stamp = now();

      await pool.query(
        `INSERT INTO supplier_profiles
         (
           company_key,
           company,
           contact_name,
           office_address,
           created_at,
           updated_at,
           updated_by
         )
         VALUES
         (
           $1,$2,$3,$4,$5,$5,$6
         )
         ON CONFLICT(company_key)
         DO UPDATE SET
           company=EXCLUDED.company,
           contact_name=EXCLUDED.contact_name,
           office_address=EXCLUDED.office_address,
           updated_at=EXCLUDED.updated_at,
           updated_by=EXCLUDED.updated_by`,
        [
          companyKey(company),
          company,
          text(req.body?.contact),
          text(req.body?.address),
          stamp,
          req.user.user_id,
        ]
      );

      await audit(
        req.user.user_id,
        'UPSERT',
        'supplier',
        companyKey(company),
        { company }
      );

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- Work Orders ---------------- */

function workKey(order) {
  return `wo:${text(order.company,200)}::${text(order.woNumber,200)}`;
}

function totalOrder(order) {
  const items =
    Array.isArray(order?.items)
      ? order.items
      : [];

  return items.reduce(
    (sum, it) =>
      sum +
      (Number(it.qty) || 0) *
        (Number(it.unitPrice) || 0),
    0
  );
}

async function saveOrder(order, userId) {
  if (
    !order ||
    typeof order !== 'object'
  ) {
    throw new Error(
      'Order data is required.'
    );
  }

  const company =
    text(order.company, 200);

  const woNumber =
    text(order.woNumber, 200);

  if (!company || !woNumber) {
    throw new Error(
      'Company and Work Order No are required.'
    );
  }

  const key =
    workKey(order);

  const client =
    await pool.connect();

  try {
    await client.query('BEGIN');

    const stamp = now();

    const supplierCompany =
      cleanCompany(order.supplierCompany);

    if (supplierCompany) {
      await client.query(
        `INSERT INTO supplier_profiles
         (
           company_key,
           company,
           contact_name,
           office_address,
           created_at,
           updated_at,
           updated_by
         )
         VALUES
         (
           $1,$2,$3,$4,$5,$5,$6
         )
         ON CONFLICT(company_key)
         DO UPDATE SET
           company=EXCLUDED.company,
           contact_name=EXCLUDED.contact_name,
           office_address=EXCLUDED.office_address,
           updated_at=EXCLUDED.updated_at,
           updated_by=EXCLUDED.updated_by`,
        [
          companyKey(supplierCompany),
          supplierCompany,
          text(order.supplierContact),
          text(order.supplierAddress),
          stamp,
          userId,
        ]
      );
    }

    const existing =
      (
        await client.query(
          `SELECT *
           FROM work_orders
           WHERE work_key=$1
           FOR UPDATE`,
          [key]
        )
      ).rows[0];

    let id;

    if (existing) {
      id = existing.id;

      await client.query(
        `UPDATE work_orders
         SET
           company=$1,
           wo_number=$2,
           data_json=$3,
           updated_at=$4,
           archived_at=NULL,
           updated_by=$5
         WHERE id=$6`,
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
      id =
        (
          await client.query(
            `INSERT INTO work_orders
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
             VALUES
             (
               $1,$2,$3,$4,$5,$5,$6,$6
             )
             RETURNING id`,
            [
              key,
              company,
              woNumber,
              order,
              stamp,
              userId,
            ]
          )
        ).rows[0].id;
    }

    const last =
      Number(
        (
          await client.query(
            `SELECT
               COALESCE(
                 MAX(version_no),
                 0
               ) AS n
             FROM work_order_versions
             WHERE work_order_id=$1`,
            [id]
          )
        ).rows[0].n
      );

    const version =
      last + 1;

    await client.query(
      `INSERT INTO work_order_versions
       (
         work_order_id,
         version_no,
         data_json,
         saved_at,
         saved_by
       )
       VALUES
       (
         $1,$2,$3,$4,$5
       )`,
      [
        id,
        version,
        order,
        stamp,
        userId,
      ]
    );

    await client.query(
      `INSERT INTO audit_log
       (
         user_id,
         action,
         entity_type,
         entity_id,
         details_json,
         created_at
       )
       VALUES
       (
         $1,$2,'work_order',$3,$4,$5
       )`,
      [
        userId,
        existing
          ? 'UPDATE'
          : 'CREATE',
        String(id),
        {
          workKey: key,
          version,
        },
        stamp,
      ]
    );

    await client.query('COMMIT');

    return {
      key,
      id,
      version,
      savedAt: stamp,
      total:
        totalOrder(order),
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

app.get(
  '/api/work-orders',
  async (req, res) => {
    try {
      const search =
        text(
          req.query?.search,
          200
        ).toLowerCase();

      const { rows } =
        await pool.query(
          `SELECT
             id,
             work_key,
             company,
             wo_number,
             data_json,
             created_at,
             updated_at,
             archived_at
           FROM work_orders
           ORDER BY updated_at DESC`
        );

      const index =
        rows
          .filter(r => !r.archived_at)
          .filter(r => {
            if (!search) return true;

            const d =
              r.data_json || {};

            return [
              r.company,
              r.wo_number,
              d.supplierCompany,
              d.styleCode,
              d.style,
            ].some(v =>
              String(v || '')
                .toLowerCase()
                .includes(search)
            );
          })
          .map(r => {
            const d =
              r.data_json || {};

            const items =
              Array.isArray(d.items)
                ? d.items
                : [];

            return {
              key: r.work_key,
              company: r.company,
              woNumber: r.wo_number,
              date:
                d.date ||
                d.deliveryDate ||
                '',
              supplierCompany:
                d.supplierCompany ||
                '',
              style:
                d.styleCode ||
                d.style ||
                (items[0]?.style || ''),
              qty:
                Number(d.quantity) ||
                items.reduce(
                  (n, it) =>
                    n +
                    (Number(it.qty) || 0),
                  0
                ),
              total:
                totalOrder(d),
              savedAt:
                r.updated_at,
              items:
                items
                  .filter(it => it.style)
                  .map(it => ({
                    style: it.style,
                    qty: it.qty,
                    unitPrice:
                      it.unitPrice,
                  })),
            };
          });

      res.json({ index });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.get(
  '/api/work-orders/:key',
  async (req, res) => {
    try {
      const r =
        (
          await pool.query(
            `SELECT *
             FROM work_orders
             WHERE work_key=$1
             AND archived_at IS NULL`,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res.status(404).json({
          error:
            'Work order not found.',
        });
      }

      res.json({
        order: r.data_json,

        meta: {
          id: r.id,
          createdAt: r.created_at,
          updatedAt: r.updated_at,
          archivedAt:
            r.archived_at,
        },
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.post(
  '/api/work-orders',
  requireEditor,
  async (req, res) => {
    try {
      const result =
        await saveOrder(
          req.body?.order,
          req.user.user_id
        );

      res.json({
        ok: true,
        ...result,
      });
    } catch (e) {
      res.status(400).json({
        error:
          e.message ||
          'Save failed.',
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
            `SELECT id
             FROM work_orders
             WHERE work_key=$1`,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res.status(404).json({
          error:
            'Work order not found.',
        });
      }

      const stamp = now();

      await pool.query(
        `UPDATE work_orders
         SET
           archived_at=$1,
           updated_at=$1,
           updated_by=$2
         WHERE id=$3`,
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

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({
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
            `SELECT id
             FROM work_orders
             WHERE work_key=$1`,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res.status(404).json({
          error:
            'Work order not found.',
        });
      }

      const { rows } =
        await pool.query(
          `SELECT
             id,
             version_no,
             saved_at,
             saved_by
           FROM work_order_versions
           WHERE work_order_id=$1
           ORDER BY version_no DESC`,
          [r.id]
        );

      res.json({
        versions: rows,
      });
    } catch (e) {
      res.status(500).json({
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
            `SELECT id
             FROM work_orders
             WHERE work_key=$1`,
            [req.params.key]
          )
        ).rows[0];

      if (!r) {
        return res.status(404).json({
          error:
            'Work order not found.',
        });
      }

      const v =
        (
          await pool.query(
            `SELECT *
             FROM work_order_versions
             WHERE work_order_id=$1
             AND version_no=$2`,
            [
              r.id,
              Number(
                req.params.version
              ),
            ]
          )
        ).rows[0];

      if (!v) {
        return res.status(404).json({
          error:
            'Version not found.',
        });
      }

      res.json({
        order: v.data_json,
        version:
          v.version_no,
        savedAt:
          v.saved_at,
        savedBy:
          v.saved_by,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- Settings ---------------- */

app.get(
  '/api/settings',
  async (req, res) => {
    try {
      const r =
        (
          await pool.query(
            `SELECT data_json
             FROM settings
             WHERE id=1`
          )
        ).rows[0];

      res.json({
        settings:
          r
            ? r.data_json
            : null,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.put(
  '/api/settings',
  requireEditor,
  async (req, res) => {
    const settings =
      req.body?.settings;

    if (
      !settings ||
      typeof settings !== 'object'
    ) {
      return res.status(400).json({
        error:
          'Invalid settings.',
      });
    }

    try {
      await pool.query(
        `INSERT INTO settings
         (
           id,
           data_json,
           updated_at,
           updated_by
         )
         VALUES
         (
           1,$1,$2,$3
         )
         ON CONFLICT(id)
         DO UPDATE SET
           data_json=EXCLUDED.data_json,
           updated_at=EXCLUDED.updated_at,
           updated_by=EXCLUDED.updated_by`,
        [
          settings,
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
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- GarmentOS module records ---------------- */

const MODULES =
  new Set([
    'materials',
    'production',
    'qc',
    'costing',
    'samples',
    'shipment',
  ]);

function validateModule(name) {
  return MODULES.has(
    String(name || '').toLowerCase()
  );
}

app.get(
  '/api/modules/:module',
  async (req, res) => {
    const module =
      String(
        req.params.module || ''
      ).toLowerCase();

    if (!validateModule(module)) {
      return res.status(404).json({
        error:
          'Unknown GarmentOS module.',
      });
    }

    try {
      const { rows } =
        await pool.query(
          `SELECT
             id,
             record_key,
             data_json,
             created_at,
             updated_at,
             archived_at,
             created_by,
             updated_by
           FROM module_records
           WHERE module=$1
           AND archived_at IS NULL
           ORDER BY updated_at DESC
           LIMIT 1000`,
          [module]
        );

      res.json({
        module,
        records: rows,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.get(
  '/api/modules/:module/:recordKey',
  async (req, res) => {
    const module =
      String(
        req.params.module || ''
      ).toLowerCase();

    if (!validateModule(module)) {
      return res.status(404).json({
        error:
          'Unknown GarmentOS module.',
      });
    }

    try {
      const r =
        (
          await pool.query(
            `SELECT *
             FROM module_records
             WHERE module=$1
             AND record_key=$2
             AND archived_at IS NULL`,
            [
              module,
              text(
                req.params.recordKey,
                200
              ),
            ]
          )
        ).rows[0];

      if (!r) {
        return res.status(404).json({
          error:
            'Record not found.',
        });
      }

      res.json({
        record: r,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.post(
  '/api/modules/:module',
  requireEditor,
  async (req, res) => {
    const module =
      String(
        req.params.module || ''
      ).toLowerCase();

    if (!validateModule(module)) {
      return res.status(404).json({
        error:
          'Unknown GarmentOS module.',
      });
    }

    const recordKey =
      text(
        req.body?.recordKey,
        200
      );

    const data =
      req.body?.data;

    if (
      !recordKey ||
      !data ||
      typeof data !== 'object'
    ) {
      return res.status(400).json({
        error:
          'recordKey and data are required.',
      });
    }

    try {
      const stamp = now();

      const r =
        await pool.query(
          `INSERT INTO module_records
           (
             module,
             record_key,
             data_json,
             created_at,
             updated_at,
             created_by,
             updated_by
           )
           VALUES
           (
             $1,$2,$3,$4,$4,$5,$5
           )
           ON CONFLICT(module,record_key)
           DO UPDATE SET
             data_json=EXCLUDED.data_json,
             updated_at=EXCLUDED.updated_at,
             updated_by=EXCLUDED.updated_by,
             archived_at=NULL
           RETURNING *`,
          [
            module,
            recordKey,
            data,
            stamp,
            req.user.user_id,
          ]
        );

      await audit(
        req.user.user_id,
        'UPSERT',
        module,
        recordKey,
        {}
      );

      res.json({
        ok: true,
        record:
          r.rows[0],
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.put(
  '/api/modules/:module/:recordKey',
  requireEditor,
  async (req, res) => {
    const module =
      String(
        req.params.module || ''
      ).toLowerCase();

    if (!validateModule(module)) {
      return res.status(404).json({
        error:
          'Unknown GarmentOS module.',
      });
    }

    const data =
      req.body?.data;

    if (
      !data ||
      typeof data !== 'object'
    ) {
      return res.status(400).json({
        error: 'data is required.',
      });
    }

    try {
      const r =
        await pool.query(
          `UPDATE module_records
           SET
             data_json=$1,
             updated_at=$2,
             updated_by=$3
           WHERE module=$4
           AND record_key=$5
           AND archived_at IS NULL
           RETURNING *`,
          [
            data,
            now(),
            req.user.user_id,
            module,
            text(
              req.params.recordKey,
              200
            ),
          ]
        );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Record not found.',
        });
      }

      await audit(
        req.user.user_id,
        'UPDATE',
        module,
        req.params.recordKey,
        {}
      );

      res.json({
        ok: true,
        record:
          r.rows[0],
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.delete(
  '/api/modules/:module/:recordKey',
  requireEditor,
  async (req, res) => {
    const module =
      String(
        req.params.module || ''
      ).toLowerCase();

    if (!validateModule(module)) {
      return res.status(404).json({
        error:
          'Unknown GarmentOS module.',
      });
    }

    try {
      const r =
        await pool.query(
          `UPDATE module_records
           SET
             archived_at=$1,
             updated_at=$1,
             updated_by=$2
           WHERE module=$3
           AND record_key=$4
           AND archived_at IS NULL
           RETURNING id`,
          [
            now(),
            req.user.user_id,
            module,
            text(
              req.params.recordKey,
              200
            ),
          ]
        );

      if (!r.rows[0]) {
        return res.status(404).json({
          error:
            'Record not found.',
        });
      }

      await audit(
        req.user.user_id,
        'ARCHIVE',
        module,
        req.params.recordKey,
        {}
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- Dashboard / reports ---------------- */

app.get(
  '/api/dashboard',
  async (req, res) => {
    try {
      const activeOrders =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM work_orders
               WHERE archived_at IS NULL`
            )
          ).rows[0].n
        );

      const workOrders =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM work_orders`
            )
          ).rows[0].n
        );

      const recent =
        (
          await pool.query(
            `SELECT
               work_key,
               company,
               wo_number,
               data_json,
               updated_at
             FROM work_orders
             WHERE archived_at IS NULL
             ORDER BY updated_at DESC
             LIMIT 20`
          )
        ).rows;

      const moduleCounts = {};

      for (const module of MODULES) {
        moduleCounts[module] =
          Number(
            (
              await pool.query(
                `SELECT COUNT(*) AS n
                 FROM module_records
                 WHERE module=$1
                 AND archived_at IS NULL`,
                [module]
              )
            ).rows[0].n
          );
      }

      res.json({
        metrics: {
          activeOrders,
          workOrders,
          materials:
            moduleCounts.materials,
          production:
            moduleCounts.production,
          qc:
            moduleCounts.qc,
          costing:
            moduleCounts.costing,
          samples:
            moduleCounts.samples,
          shipment:
            moduleCounts.shipment,
        },

        recentWorkOrders:
          recent.map(r => ({
            key: r.work_key,
            company: r.company,
            woNumber:
              r.wo_number,
            data:
              r.data_json,
            updatedAt:
              r.updated_at,
          })),

        moduleCounts,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.get(
  '/api/reports/summary',
  async (req, res) => {
    try {
      const suppliers =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM supplier_profiles`
            )
          ).rows[0].n
        );

      const activeOrders =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM work_orders
               WHERE archived_at IS NULL`
            )
          ).rows[0].n
        );

      const archivedOrders =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM work_orders
               WHERE archived_at IS NOT NULL`
            )
          ).rows[0].n
        );

      res.json({
        generatedAt: now(),
        suppliers,
        activeOrders,
        archivedOrders,

        modules:
          Object.fromEntries(
            await Promise.all(
              [...MODULES].map(
                async m => [
                  m,
                  Number(
                    (
                      await pool.query(
                        `SELECT COUNT(*) AS n
                         FROM module_records
                         WHERE module=$1
                         AND archived_at IS NULL`,
                        [m]
                      )
                    ).rows[0].n,
                  ),
                ]
              )
            )
          ),
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- SaRa AI data endpoint ---------------- */

app.post(
  '/api/ai/ask',
  requireLogin,
  async (req, res) => {
    try {
      const question =
        text(
          req.body?.question,
          1000
        );

      if (!question) {
        return res.status(400).json({
          error:
            'Question is required.',
        });
      }

      const q =
        question.toLowerCase();

      const activeOrders =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM work_orders
               WHERE archived_at IS NULL`
            )
          ).rows[0].n
        );

      const suppliers =
        Number(
          (
            await pool.query(
              `SELECT COUNT(*) AS n
               FROM supplier_profiles`
            )
          ).rows[0].n
        );

      let answer =
        `SaRa database currently contains ${activeOrders} active work orders and ${suppliers} supplier profiles. ` +
        `For a reliable operational decision, review work-order dates, material records, production progress and QC records together.`;

      if (q.includes('risk')) {
        const rows =
          (
            await pool.query(
              `SELECT
                 wo_number,
                 company,
                 data_json
               FROM work_orders
               WHERE archived_at IS NULL
               ORDER BY updated_at DESC
               LIMIT 20`
            )
          ).rows;

        const risky =
          rows
            .filter(r => {
              const d =
                r.data_json || {};

              const s =
                `${d.status || ''} ${d.risk || ''} ${d.qcStatus || ''}`
                  .toLowerCase();

              return /risk|late|pending|blocked|critical/.test(s);
            })
            .slice(0, 5);

        answer =
          risky.length
            ? `Potential risk records found: ${risky
                .map(
                  r =>
                    `${r.wo_number} (${r.company})`
                )
                .join(', ')}.`
            : 'No work orders were explicitly marked with risk, late, blocked, critical or pending indicators in the stored data.';
      } else if (q.includes('supplier')) {
        const rows =
          (
            await pool.query(
              `SELECT company
               FROM supplier_profiles
               ORDER BY company
               LIMIT 10`
            )
          ).rows;

        answer =
          rows.length
            ? `Supplier records currently available include: ${rows
                .map(r => r.company)
                .join(', ')}.`
            : 'No supplier profiles are currently stored.';
      } else if (q.includes('material')) {
        const n =
          Number(
            (
              await pool.query(
                `SELECT COUNT(*) AS n
                 FROM module_records
                 WHERE module='materials'
                 AND archived_at IS NULL`
              )
            ).rows[0].n
          );

        answer =
          `There are ${n} active material records in SaRa. Check records with pending, balance, shortage or critical status first.`;
      } else if (q.includes('production')) {
        const n =
          Number(
            (
              await pool.query(
                `SELECT COUNT(*) AS n
                 FROM module_records
                 WHERE module='production'
                 AND archived_at IS NULL`
              )
            ).rows[0].n
          );

        answer =
          `There are ${n} active production records in SaRa. Compare planned quantity with cutting, sewing, finishing and ready quantities before allocating capacity.`;
      } else if (
        q.includes('qc') ||
        q.includes('quality')
      ) {
        const n =
          Number(
            (
              await pool.query(
                `SELECT COUNT(*) AS n
                 FROM module_records
                 WHERE module='qc'
                 AND archived_at IS NULL`
              )
            ).rows[0].n
          );

        answer =
          `There are ${n} active QC/QA records in SaRa. Review pending gates and high-defect records first.`;
      }

      await audit(
        req.user.user_id,
        'AI_QUERY',
        'ai',
        null,
        { question }
      );

      res.json({
        ok: true,
        question,
        answer,
        generatedAt: now(),
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- Audit ---------------- */

app.get(
  '/api/audit',
  requireAdmin,
  async (req, res) => {
    try {
      const { rows } =
        await pool.query(
          `SELECT
             id,
             action,
             entity_type,
             entity_id,
             created_at,
             user_id,
             details_json
           FROM audit_log
           ORDER BY created_at DESC
           LIMIT 500`
        );

      res.json({
        audit: rows,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

/* ---------------- Health / static app ---------------- */

app.get(
  '/api/health',
  async (req, res) => {
    try {
      await pool.query('SELECT 1');

      res.json({
        ok: true,
        database: true,
        time: now(),
      });
    } catch (e) {
      res.status(503).json({
        ok: false,
        database: false,
      });
    }
  }
);

app.use(
  express.static(
    path.join(ROOT, 'public')
  )
);

app.get(
  '/{*splat}',
  (req, res) => {
    res.sendFile(
      path.join(
        ROOT,
        'public',
        'app.html'
      )
    );
  }
);

initDb()
  .then(() => {
    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `SaRa GarmentOS server running on port ${PORT}`
        );
      }
    );
  })
  .catch(err => {
    console.error(
      'Database initialization failed:',
      err
    );

    process.exit(1);
  });
