require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must contain at least 32 characters");
}

if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
  throw new Error("ADMIN_USERNAME and ADMIN_PASSWORD are required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
  max: Number(process.env.DB_POOL_MAX || 10),
});

app.set("trust proxy", 1);

app.use(
  express.json({
    limit: "10mb",
  })
);

/* =========================================================
   HELPERS
========================================================= */

function now() {
  return new Date();
}

function clean(v) {
  return String(v ?? "").trim();
}

function cleanUsername(v) {
  return clean(v)
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "");
}

function makeId(prefix) {
  return (
    prefix +
    "_" +
    crypto.randomBytes(12).toString("hex")
  );
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password, salt = null) {
  const realSalt =
    salt || crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(
      String(password),
      realSalt,
      64
    )
    .toString("hex");

  return {
    salt: realSalt,
    hash,
  };
}

function verifyPassword(password, hash, salt) {
  const calculated = crypto
    .scryptSync(
      String(password),
      salt,
      64
    )
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(calculated, "hex"),
    Buffer.from(hash, "hex")
  );
}

/* =========================================================
   SESSION
========================================================= */

const SESSION_TTL =
  Number(process.env.SESSION_TTL_SECONDS || 28800);

function createSession(user) {
  const payload = {
    userId: user.user_id,
    username: user.username,
    role: user.role,
    exp:
      Math.floor(Date.now() / 1000) +
      SESSION_TTL,
  };

  const body = Buffer.from(
    JSON.stringify(payload)
  ).toString("base64url");

  const signature = crypto
    .createHmac(
      "sha256",
      process.env.SESSION_SECRET
    )
    .update(body)
    .digest("base64url");

  return `${body}.${signature}`;
}

function readSession(token) {
  try {
    if (!token) return null;

    const [body, signature] =
      token.split(".");

    if (!body || !signature) return null;

    const expected = crypto
      .createHmac(
        "sha256",
        process.env.SESSION_SECRET
      )
      .update(body)
      .digest("base64url");

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString()
    );

    if (
      !payload.exp ||
      payload.exp < Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function setSession(res, user) {
  const token = createSession(user);

  res.cookie(
    "wo_session",
    token,
    {
      httpOnly: true,
      sameSite: "strict",
      secure:
        process.env.NODE_ENV === "production",
      maxAge: SESSION_TTL * 1000,
      path: "/",
    }
  );
}

function clearSession(res) {
  res.clearCookie(
    "wo_session",
    {
      httpOnly: true,
      sameSite: "strict",
      secure:
        process.env.NODE_ENV === "production",
      path: "/",
    }
  );
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

async function optionalAuth(req, res, next) {
  const token = req.cookies?.wo_session;

  req.user = readSession(token);

  next();
}

function requireLogin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: "Login required",
    });
  }

  next();
}

function requireEditor(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: "Editor login required",
    });
  }

  if (
    req.user.role !== "editor" &&
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      error: "Editor permission required",
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: "Admin login required",
    });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin permission required",
    });
  }

  next();
}

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      role TEXT NOT NULL
        CHECK(role IN ('admin','editor')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS work_orders (
      id BIGSERIAL PRIMARY KEY,
      work_key TEXT UNIQUE NOT NULL,
      company TEXT NOT NULL DEFAULT '',
      wo_number TEXT NOT NULL DEFAULT '',
      data_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      created_by TEXT,
      updated_by TEXT,
      archived_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS work_order_versions (
      id BIGSERIAL PRIMARY KEY,
      work_order_id BIGINT NOT NULL,
      version_no INTEGER NOT NULL,
      data_json JSONB NOT NULL,
      saved_at TIMESTAMPTZ NOT NULL,
      saved_by TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      user_id TEXT,
      details_json JSONB,
      created_at TIMESTAMPTZ NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS supplier_profiles (
      company_key TEXT PRIMARY KEY,
      company TEXT NOT NULL DEFAULT '',
      contact_name TEXT NOT NULL DEFAULT '',
      office_address TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      updated_by TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS module_records (
      id BIGSERIAL PRIMARY KEY,
      module TEXT NOT NULL,
      record_key TEXT NOT NULL,
      data_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      created_by TEXT,
      updated_by TEXT,
      UNIQUE(module, record_key)
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_work_orders_updated
    ON work_orders(updated_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_modules_module
    ON module_records(module)
  `);

  /* CREATE ADMIN AUTOMATICALLY */

  const adminUsername =
    cleanUsername(
      process.env.ADMIN_USERNAME
    );

  const existing =
    await pool.query(
      `
      SELECT user_id
      FROM users
      WHERE username=$1
      `,
      [adminUsername]
    );

  if (!existing.rows.length) {
    const hp = hashPassword(
      process.env.ADMIN_PASSWORD
    );

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
      VALUES
      ($1,$2,$3,$4,'admin',TRUE,$5,$5)
      `,
      [
        makeId("usr"),
        adminUsername,
        hp.hash,
        hp.salt,
        stamp,
      ]
    );

    console.log(
      `Admin created: ${adminUsername}`
    );
  }
}

/* =========================================================
   COOKIE PARSER
========================================================= */

app.use((req, res, next) => {
  const header =
    req.headers.cookie || "";

  const cookies = {};

  header
    .split(";")
    .forEach(part => {
      const index = part.indexOf("=");

      if (index === -1) return;

      const key =
        part.slice(0, index).trim();

      const value =
        part.slice(index + 1).trim();

      cookies[key] =
        decodeURIComponent(value);
    });

  req.cookies = cookies;

  next();
});

app.use(optionalAuth);

/* =========================================================
   LOGIN
========================================================= */

const failedLogins = new Map();

function loginAllowed(ip) {
  const data =
    failedLogins.get(ip);

  if (!data) return true;

  if (
    Date.now() - data.first >
    15 * 60 * 1000
  ) {
    failedLogins.delete(ip);
    return true;
  }

  return data.count < 10;
}

function failedLogin(ip) {
  const data =
    failedLogins.get(ip);

  if (
    !data ||
    Date.now() - data.first >
      15 * 60 * 1000
  ) {
    failedLogins.set(ip, {
      first: Date.now(),
      count: 1,
    });
  } else {
    data.count++;
  }
}

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const ip =
        req.ip || "unknown";

      if (!loginAllowed(ip)) {
        return res.status(429).json({
          error:
            "Too many login attempts. Try again later.",
        });
      }

      const username =
        cleanUsername(
          req.body?.username
        );

      const password =
        String(
          req.body?.password || ""
        );

      if (!username || !password) {
        return res.status(400).json({
          error:
            "Username and password are required",
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE username=$1
          LIMIT 1
          `,
          [username]
        );

      const user =
        result.rows[0];

      if (
        !user ||
        !user.active ||
        !verifyPassword(
          password,
          user.password_hash,
          user.password_salt
        )
      ) {
        failedLogin(ip);

        return res.status(401).json({
          error:
            "Invalid username or password",
        });
      }

      failedLogins.delete(ip);

      setSession(res, user);

      await pool.query(
        `
        INSERT INTO audit_log
        (
          action,
          entity_type,
          entity_id,
          user_id,
          details_json,
          created_at
        )
        VALUES
        ('LOGIN','user',$1,$1,$2,$3)
        `,
        [
          user.user_id,
          JSON.stringify({
            username:
              user.username,
          }),
          now(),
        ]
      );

      res.json({
        ok: true,
        user: {
          userId:
            user.user_id,
          username:
            user.username,
          role:
            user.role,
        },
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "Login failed",
      });
    }
  }
);

app.post(
  "/api/logout",
  async (req, res) => {
    clearSession(res);

    res.json({
      ok: true,
    });
  }
);

app.get(
  "/api/me",
  (req, res) => {
    if (!req.user) {
      return res.json({
        loggedIn: false,
      });
    }

    res.json({
      loggedIn: true,
      user: {
        userId:
          req.user.userId,
        username:
          req.user.username,
        role:
          req.user.role,
      },
    });
  }
);

/* =========================================================
   USERS / ADMIN
========================================================= */

app.get(
  "/api/users",
  requireAdmin,
  async (req, res) => {
    const { rows } =
      await pool.query(`
        SELECT
          user_id,
          username,
          role,
          active,
          created_at,
          updated_at
        FROM users
        ORDER BY username
      `);

    res.json({
      users: rows,
    });
  }
);

app.post(
  "/api/users",
  requireAdmin,
  async (req, res) => {
    try {
      const username =
        cleanUsername(
          req.body?.username
        );

      const password =
        String(
          req.body?.password || ""
        );

      if (
        username.length < 3 ||
        password.length < 8
      ) {
        return res.status(400).json({
          error:
            "Username must be 3+ characters and password 8+ characters",
        });
      }

      const hp =
        hashPassword(password);

      const stamp = now();

      const result =
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
          VALUES
          ($1,$2,$3,$4,'editor',TRUE,$5,$5)
          RETURNING
            user_id,
            username,
            role,
            active
          `,
          [
            makeId("usr"),
            username,
            hp.hash,
            hp.salt,
            stamp,
          ]
        );

      res.json({
        ok: true,
        user:
          result.rows[0],
      });
    } catch (err) {
      res.status(400).json({
        error:
          "Unable to create Editor. Username may already exist.",
      });
    }
  }
);

app.put(
  "/api/users/:userId/password",
  requireAdmin,
  async (req, res) => {
    const password =
      String(
        req.body?.password || ""
      );

    if (password.length < 8) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters",
      });
    }

    const hp =
      hashPassword(password);

    await pool.query(
      `
      UPDATE users
      SET
        password_hash=$1,
        password_salt=$2,
        updated_at=$3
      WHERE user_id=$4
      `,
      [
        hp.hash,
        hp.salt,
        now(),
        req.params.userId,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

app.put(
  "/api/users/:userId/active",
  requireAdmin,
  async (req, res) => {
    const active =
      Boolean(req.body?.active);

    if (
      req.params.userId ===
      req.user.userId
    ) {
      return res.status(400).json({
        error:
          "You cannot disable your own account",
      });
    }

    await pool.query(
      `
      UPDATE users
      SET
        active=$1,
        updated_at=$2
      WHERE user_id=$3
      `,
      [
        active,
        now(),
        req.params.userId,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

/* =========================================================
   WORK ORDERS - VIEWER ACCESS
========================================================= */

app.get(
  "/api/work-orders",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
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
          WHERE archived_at IS NULL
          ORDER BY updated_at DESC
        `);

      const index =
        result.rows.map(row => {
          const d =
            row.data_json || {};

          const items =
            Array.isArray(d.items)
              ? d.items
              : [];

          const total =
            items.reduce(
              (sum, item) =>
                sum +
                (Number(item.qty) || 0) *
                (Number(item.unitPrice) || 0),
              0
            );

          return {
            key:
              row.work_key,

            company:
              row.company,

            woNumber:
              row.wo_number,

            date:
              d.date || "",

            supplierCompany:
              d.supplierCompany || "",

            total,

            savedAt:
              row.updated_at,

            items:
              items
                .filter(
                  item => item.style
                )
                .map(item => ({
                  style:
                    item.style,
                  qty:
                    item.qty,
                  unitPrice:
                    item.unitPrice,
                })),
          };
        });

      res.json({
        index,
      });
    } catch (err) {
      res.status(500).json({
        error: err.message,
      });
    }
  }
);

app.get(
  "/api/work-orders/:key",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM work_orders
          WHERE work_key=$1
          AND archived_at IS NULL
          LIMIT 1
          `,
          [req.params.key]
        );

      if (!result.rows[0]) {
        return res.status(404).json({
          error:
            "Work order not found",
        });
      }

      const row =
        result.rows[0];

      res.json({
        order:
          row.data_json,

        meta: {
          id:
            row.id,

          createdAt:
            row.created_at,

          updatedAt:
            row.updated_at,

          archivedAt:
            row.archived_at,
        },
      });
    } catch (err) {
      res.status(500).json({
        error: err.message,
      });
    }
  }
);

/* =========================================================
   SAVE WORK ORDER - EDITOR
========================================================= */

app.post(
  "/api/work-orders",
  requireEditor,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const order =
        req.body?.order;

      if (!order) {
        return res.status(400).json({
          error:
            "Order data is required",
        });
      }

      const workKey =
        clean(
          order.workKey ||
          order.key
        ) ||
        makeId("wo");

      const company =
        clean(
          order.company ||
          order.buyer ||
          ""
        );

      const woNumber =
        clean(
          order.woNumber ||
          order.workOrderNumber ||
          ""
        );

      await client.query(
        "BEGIN"
      );

      const existing =
        await client.query(
          `
          SELECT *
          FROM work_orders
          WHERE work_key=$1
          LIMIT 1
          `,
          [workKey]
        );

      const stamp = now();

      let workOrderId;
      let versionNo = 1;

      if (!existing.rows.length) {
        const inserted =
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
            VALUES
            ($1,$2,$3,$4,$5,$5,$6,$6)
            RETURNING id
            `,
            [
              workKey,
              company,
              woNumber,
              JSON.stringify(order),
              stamp,
              req.user.userId,
            ]
          );

        workOrderId =
          inserted.rows[0].id;
      } else {
        workOrderId =
          existing.rows[0].id;

        const count =
          await client.query(
            `
            SELECT COALESCE(
              MAX(version_no),0
            ) AS max_version
            FROM work_order_versions
            WHERE work_order_id=$1
            `,
            [workOrderId]
          );

        versionNo =
          Number(
            count.rows[0].max_version
          ) + 1;

        await client.query(
          `
          UPDATE work_orders
          SET
            company=$1,
            wo_number=$2,
            data_json=$3,
            updated_at=$4,
            updated_by=$5,
            archived_at=NULL
          WHERE id=$6
          `,
          [
            company,
            woNumber,
            JSON.stringify(order),
            stamp,
            req.user.userId,
            workOrderId,
          ]
        );
      }

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
        VALUES
        ($1,$2,$3,$4,$5)
        `,
        [
          workOrderId,
          versionNo,
          JSON.stringify(order),
          stamp,
          req.user.userId,
        ]
      );

      await client.query(
        `
        INSERT INTO audit_log
        (
          action,
          entity_type,
          entity_id,
          user_id,
          details_json,
          created_at
        )
        VALUES
        ('SAVE','work_order',$1,$2,$3,$4)
        `,
        [
          String(workOrderId),
          req.user.userId,
          JSON.stringify({
            workKey,
            version:
              versionNo,
          }),
          stamp,
        ]
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok: true,
        key: workKey,
        id: workOrderId,
        version: versionNo,
        savedAt: stamp,
      });
    } catch (err) {
      await client.query(
        "ROLLBACK"
      );

      console.error(err);

      res.status(400).json({
        error:
          err.message ||
          "Save failed",
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ARCHIVE WORK ORDER
========================================================= */

app.delete(
  "/api/work-orders/:key",
  requireEditor,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE work_orders
          SET
            archived_at=$1,
            updated_at=$1,
            updated_by=$2
          WHERE work_key=$3
          RETURNING id
          `,
          [
            now(),
            req.user.userId,
            req.params.key,
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Work order not found",
        });
      }

      res.json({
        ok: true,
      });
    } catch (err) {
      res.status(500).json({
        error: err.message,
      });
    }
  }
);

/* =========================================================
   WORK ORDER HISTORY
========================================================= */

app.get(
  "/api/work-orders/:key/versions",
  requireLogin,
  async (req, res) => {
    const order =
      await pool.query(
        `
        SELECT id
        FROM work_orders
        WHERE work_key=$1
        `,
        [req.params.key]
      );

    if (!order.rows.length) {
      return res.status(404).json({
        error:
          "Work order not found",
      });
    }

    const versions =
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
        [order.rows[0].id]
      );

    res.json({
      versions:
        versions.rows,
    });
  }
);

app.get(
  "/api/work-orders/:key/versions/:version",
  requireLogin,
  async (req, res) => {
    const result =
      await pool.query(
        `
        SELECT
          v.*
        FROM work_order_versions v
        JOIN work_orders w
          ON w.id=v.work_order_id
        WHERE
          w.work_key=$1
          AND v.version_no=$2
        LIMIT 1
        `,
        [
          req.params.key,
          Number(
            req.params.version
          ),
        ]
      );

    if (!result.rows.length) {
      return res.status(404).json({
        error:
          "Version not found",
      });
    }

    res.json({
      version:
        result.rows[0],
    });
  }
);

/* =========================================================
   SUPPLIERS
========================================================= */

function supplierKey(company) {
  return clean(company)
    .toLowerCase();
}

app.get(
  "/api/suppliers",
  async (req, res) => {
    try {
      const search =
        supplierKey(
          req.query?.search
        );

      const limit =
        Math.min(
          100,
          Math.max(
            1,
            Number(
              req.query?.limit
            ) || 20
          )
        );

      let query = `
        SELECT
          company,
          contact_name,
          office_address,
          updated_at
        FROM supplier_profiles
      `;

      const params = [];

      if (search) {
        params.push(
          `%${search}%`
        );

        query +=
          ` WHERE company_key LIKE $1 `;
      }

      query +=
        ` ORDER BY company LIMIT ${limit}`;

      const result =
        await pool.query(
          query,
          params
        );

      res.json({
        suppliers:
          result.rows.map(r => ({
            company:
              r.company,
            contact:
              r.contact_name,
            address:
              r.office_address,
            updatedAt:
              r.updated_at,
          })),
      });
    } catch (err) {
      res.status(500).json({
        error: err.message,
      });
    }
  }
);

app.get(
  "/api/suppliers/by-company",
  async (req, res) => {
    const company =
      clean(
        req.query?.company
      );

    if (!company) {
      return res.json({
        supplier: null,
      });
    }

    const result =
      await pool.query(
        `
        SELECT *
        FROM supplier_profiles
        WHERE company_key=$1
        LIMIT 1
        `,
        [supplierKey(company)]
      );

    if (!result.rows.length) {
      return res.json({
        supplier: null,
      });
    }

    const row =
      result.rows[0];

    res.json({
      supplier: {
        company:
          row.company,
        contact:
          row.contact_name,
        address:
          row.office_address,
        updatedAt:
          row.updated_at,
      },
    });
  }
);

app.put(
  "/api/suppliers",
  requireEditor,
  async (req, res) => {
    const company =
      clean(
        req.body?.company
      );

    if (!company) {
      return res.status(400).json({
        error:
          "Supplier company is required",
      });
    }

    const contact =
      clean(
        req.body?.contact
      );

    const address =
      clean(
        req.body?.address
      );

    const stamp = now();

    await pool.query(
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
      VALUES
      ($1,$2,$3,$4,$5,$5,$6)
      ON CONFLICT(company_key)
      DO UPDATE SET
        company=$2,
        contact_name=$3,
        office_address=$4,
        updated_at=$5,
        updated_by=$6
      `,
      [
        supplierKey(company),
        company,
        contact,
        address,
        stamp,
        req.user.userId,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

/* =========================================================
   GARMENTOS MODULES
========================================================= */

const MODULES = new Set([
  "materials",
  "production",
  "qc",
  "costing",
  "samples",
  "shipment",
]);

function validModule(module) {
  return MODULES.has(
    String(module)
  );
}

app.get(
  "/api/modules/:module",
  async (req, res) => {
    if (
      !validModule(
        req.params.module
      )
    ) {
      return res.status(404).json({
        error:
          "Invalid module",
      });
    }

    const result =
      await pool.query(
        `
        SELECT
          record_key,
          data_json,
          created_at,
          updated_at
        FROM module_records
        WHERE module=$1
        ORDER BY updated_at DESC
        `,
        [req.params.module]
      );

    res.json({
      records:
        result.rows.map(r => ({
          key:
            r.record_key,
          data:
            r.data_json,
          createdAt:
            r.created_at,
          updatedAt:
            r.updated_at,
        })),
    });
  }
);

app.get(
  "/api/modules/:module/:recordKey",
  async (req, res) => {
    if (
      !validModule(
        req.params.module
      )
    ) {
      return res.status(404).json({
        error:
          "Invalid module",
      });
    }

    const result =
      await pool.query(
        `
        SELECT *
        FROM module_records
        WHERE
          module=$1
          AND record_key=$2
        LIMIT 1
        `,
        [
          req.params.module,
          req.params.recordKey,
        ]
      );

    if (!result.rows.length) {
      return res.status(404).json({
        error:
          "Record not found",
      });
    }

    res.json({
      record:
        result.rows[0],
    });
  }
);

app.post(
  "/api/modules/:module",
  requireEditor,
  async (req, res) => {
    if (
      !validModule(
        req.params.module
      )
    ) {
      return res.status(404).json({
        error:
          "Invalid module",
      });
    }

    const key =
      clean(
        req.body?.key
      ) ||
      makeId("rec");

    const data =
      req.body?.data || {};

    const stamp = now();

    await pool.query(
      `
      INSERT INTO module_records
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
      ($1,$2,$3,$4,$4,$5,$5)
      ON CONFLICT(module,record_key)
      DO UPDATE SET
        data_json=$3,
        updated_at=$4,
        updated_by=$5
      `,
      [
        req.params.module,
        key,
        JSON.stringify(data),
        stamp,
        req.user.userId,
      ]
    );

    res.json({
      ok: true,
      key,
    });
  }
);

app.put(
  "/api/modules/:module/:recordKey",
  requireEditor,
  async (req, res) => {
    if (
      !validModule(
        req.params.module
      )
    ) {
      return res.status(404).json({
        error:
          "Invalid module",
      });
    }

    await pool.query(
      `
      UPDATE module_records
      SET
        data_json=$1,
        updated_at=$2,
        updated_by=$3
      WHERE
        module=$4
        AND record_key=$5
      `,
      [
        JSON.stringify(
          req.body?.data || {}
        ),
        now(),
        req.user.userId,
        req.params.module,
        req.params.recordKey,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

app.delete(
  "/api/modules/:module/:recordKey",
  requireEditor,
  async (req, res) => {
    if (
      !validModule(
        req.params.module
      )
    ) {
      return res.status(404).json({
        error:
          "Invalid module",
      });
    }

    await pool.query(
      `
      DELETE FROM module_records
      WHERE
        module=$1
        AND record_key=$2
      `,
      [
        req.params.module,
        req.params.recordKey,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

/* =========================================================
   DASHBOARD
========================================================= */

app.get(
  "/api/dashboard",
  async (req, res) => {
    const workOrders =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM work_orders
        WHERE archived_at IS NULL
      `);

    const suppliers =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM supplier_profiles
      `);

    const materials =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM module_records
        WHERE module='materials'
      `);

    const production =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM module_records
        WHERE module='production'
      `);

    const qc =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM module_records
        WHERE module='qc'
      `);

    res.json({
      workOrders:
        workOrders.rows[0].count,

      suppliers:
        suppliers.rows[0].count,

      materials:
        materials.rows[0].count,

      production:
        production.rows[0].count,

      qc:
        qc.rows[0].count,
    });
  }
);

/* =========================================================
   REPORTS
========================================================= */

app.get(
  "/api/reports/summary",
  requireLogin,
  async (req, res) => {
    const result =
      await pool.query(`
        SELECT
          COUNT(*) FILTER (
            WHERE archived_at IS NULL
          )::int AS active_work_orders,

          COUNT(*) FILTER (
            WHERE archived_at IS NOT NULL
          )::int AS archived_work_orders,

          COUNT(*)::int AS total_work_orders
        FROM work_orders
      `);

    res.json({
      summary:
        result.rows[0],
    });
  }
);

/* =========================================================
   AUDIT LOG
========================================================= */

app.get(
  "/api/audit",
  requireAdmin,
  async (req, res) => {
    const result =
      await pool.query(`
        SELECT
          id,
          action,
          entity_type,
          entity_id,
          user_id,
          details_json,
          created_at
        FROM audit_log
        ORDER BY created_at DESC
        LIMIT 500
      `);

    res.json({
      audit:
        result.rows,
    });
  }
);

/* =========================================================
   SETTINGS
========================================================= */

app.get(
  "/api/settings",
  requireLogin,
  async (req, res) => {
    res.json({
      appName:
        "SaRa GarmentOS",
      version:
        "2.0",
    });
  }
);

/* =========================================================
   AI ASSISTANT
========================================================= */

app.post(
  "/api/ai/ask",
  requireLogin,
  async (req, res) => {
    const question =
      clean(
        req.body?.question
      );

    if (!question) {
      return res.status(400).json({
        error:
          "Question is required",
      });
    }

    const orders =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM work_orders
        WHERE archived_at IS NULL
      `);

    const suppliers =
      await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM supplier_profiles
      `);

    const answer =
      `SaRa AI currently sees ` +
      `${orders.rows[0].count} active work orders ` +
      `and ${suppliers.rows[0].count} supplier records. ` +
      `For operational decisions, review materials, ` +
      `production progress, QC status and delivery dates together.`;

    res.json({
      answer,
    });
  }
);

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      res.json({
        ok: true,
        database: "connected",
        service:
          "SaRa GarmentOS",
      });
    } catch (err) {
      res.status(503).json({
        ok: false,
        database:
          "disconnected",
      });
    }
  }
);

/* =========================================================
   STATIC FRONTEND
========================================================= */

app.use(
  express.static(
    PUBLIC_DIR
  )
);

app.get(
  "/*splat",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "app.html"
      )
    );
  }
);

/* =========================================================
   START
========================================================= */

async function start() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `SaRa GarmentOS running on port ${PORT}`
        );
      }
    );
  } catch (err) {
    console.error(
      "SERVER START FAILED:",
      err
    );

    process.exit(1);
  }
}

start();
