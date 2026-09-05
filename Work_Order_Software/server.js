require('dotenv').config();
const path = require('path');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required. Set it in your hosting provider.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 5,
});

const now = () => new Date().toISOString();
function safeJson(s) { try { return JSON.parse(s); } catch { return null; } }

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
      work_order_id BIGINT NOT NULL REFERENCES work_orders(id) ON DELETE CASCADE,
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
    CREATE INDEX IF NOT EXISTS idx_work_orders_updated ON work_orders(updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_versions_order ON work_order_versions(work_order_id, version_no DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
  `);
}

const LOCAL_USER = { id: 'local-user', user_id: 'local-user', role: 'admin', active: 1 };
function auth(req, res, next) { req.user = LOCAL_USER; next(); }

async function audit(userId, action, entityType, entityId, details) {
  await pool.query(
    'INSERT INTO audit_log(user_id,action,entity_type,entity_id,details_json,created_at) VALUES($1,$2,$3,$4,$5,$6)',
    [userId || null, action, entityType, entityId == null ? null : String(entityId), details || {}, now()]
  );
}

app.use(express.json({ limit: '2mb' }));

// Compatibility endpoint: this version intentionally has no login.
app.post('/api/login', (req, res) => res.json({ user: { userId: 'local-user', role: 'admin' } }));
app.post('/api/logout', (req, res) => res.json({ ok: true }));
app.get('/api/me', auth, (req, res) => res.json({ user: { userId: req.user.user_id, role: req.user.role } }));

app.get('/api/settings', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data_json FROM settings WHERE id=1');
    res.json({ settings: rows[0] ? rows[0].data_json : null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/settings', auth, async (req, res) => {
  const data = req.body && req.body.settings;
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'Invalid settings' });
  try {
    await pool.query(`INSERT INTO settings(id,data_json,updated_at,updated_by) VALUES(1,$1,$2,$3)
      ON CONFLICT(id) DO UPDATE SET data_json=EXCLUDED.data_json,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by`,
      [data, now(), req.user.id]);
    await audit(req.user.id, 'UPDATE', 'settings', '1', {});
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/work-orders', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id,work_key,company,wo_number,data_json,created_at,updated_at,archived_at
      FROM work_orders ORDER BY updated_at DESC`);
    const index = rows.filter(r => !r.archived_at).map(r => {
      const d = r.data_json || {};
      const items = Array.isArray(d.items) ? d.items : [];
      return {
        key: r.work_key, company: r.company, woNumber: r.wo_number, date: d.date || '',
        supplierCompany: d.supplierCompany || '',
        total: items.reduce((sum, it) => sum + (Number(it.qty) || 0) * (Number(it.unitPrice) || 0), 0),
        savedAt: r.updated_at, items: items.filter(it => it.style).map(it => ({ style: it.style, qty: it.qty, unitPrice: it.unitPrice }))
      };
    });
    res.json({ index });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/work-orders/:key', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM work_orders WHERE work_key=$1', [req.params.key]);
    if (!rows[0]) return res.status(404).json({ error: 'Work order not found' });
    const r = rows[0];
    res.json({ order: r.data_json, meta: { id: r.id, createdAt: r.created_at, updatedAt: r.updated_at, archivedAt: r.archived_at } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

async function saveOrder(order) {
  const company = String(order.company || '').trim();
  const woNumber = String(order.woNumber || '').trim();
  if (!company || !woNumber) throw new Error('Company and Work Order No are required.');
  const key = `wo:${company}::${woNumber}`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const stamp = now();
    const existing = (await client.query('SELECT * FROM work_orders WHERE work_key=$1 FOR UPDATE', [key])).rows[0];
    let id;
    if (existing) {
      id = existing.id;
      await client.query(`UPDATE work_orders SET company=$1,wo_number=$2,data_json=$3,updated_at=$4,archived_at=NULL,updated_by=$5 WHERE id=$6`,
        [company, woNumber, order, stamp, LOCAL_USER.id, id]);
    } else {
      const r = await client.query(`INSERT INTO work_orders(work_key,company,wo_number,data_json,created_at,updated_at,created_by,updated_by)
        VALUES($1,$2,$3,$4,$5,$5,$6,$6) RETURNING id`, [key, company, woNumber, order, stamp, LOCAL_USER.id]);
      id = r.rows[0].id;
    }
    const last = Number((await client.query('SELECT COALESCE(MAX(version_no),0) AS n FROM work_order_versions WHERE work_order_id=$1', [id])).rows[0].n);
    const version = last + 1;
    await client.query(`INSERT INTO work_order_versions(work_order_id,version_no,data_json,saved_at,saved_by) VALUES($1,$2,$3,$4,$5)`,
      [id, version, order, stamp, LOCAL_USER.id]);
    await client.query(`INSERT INTO audit_log(user_id,action,entity_type,entity_id,details_json,created_at) VALUES($1,$2,$3,$4,$5,$6)`,
      [LOCAL_USER.id, existing ? 'UPDATE' : 'CREATE', 'work_order', String(id), { workKey: key, version }, stamp]);
    await client.query('COMMIT');
    return { key, id, version, savedAt: stamp };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally { client.release(); }
}

app.post('/api/work-orders', auth, async (req, res) => {
  try {
    const order = req.body && req.body.order;
    if (!order) return res.status(400).json({ error: 'Order data is required' });
    const result = await saveOrder(order);
    res.json({ ok: true, ...result });
  } catch (e) { res.status(400).json({ error: e.message || 'Save failed' }); }
});

app.get('/api/work-orders/:key/versions', auth, async (req, res) => {
  try {
    const r = (await pool.query('SELECT id FROM work_orders WHERE work_key=$1', [req.params.key])).rows[0];
    if (!r) return res.status(404).json({ error: 'Work order not found' });
    const { rows } = await pool.query(`SELECT id,version_no,saved_at,saved_by FROM work_order_versions
      WHERE work_order_id=$1 ORDER BY version_no DESC`, [r.id]);
    res.json({ versions: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/work-orders/:key/versions/:version', auth, async (req, res) => {
  try {
    const r = (await pool.query('SELECT id FROM work_orders WHERE work_key=$1', [req.params.key])).rows[0];
    if (!r) return res.status(404).json({ error: 'Work order not found' });
    const v = (await pool.query('SELECT * FROM work_order_versions WHERE work_order_id=$1 AND version_no=$2', [r.id, Number(req.params.version)])).rows[0];
    if (!v) return res.status(404).json({ error: 'Version not found' });
    res.json({ order: v.data_json, version: v.version_no, savedAt: v.saved_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/work-orders/:key', auth, async (req, res) => {
  try {
    const r = (await pool.query('SELECT id FROM work_orders WHERE work_key=$1', [req.params.key])).rows[0];
    if (!r) return res.status(404).json({ error: 'Work order not found' });
    const stamp = now();
    await pool.query('UPDATE work_orders SET archived_at=$1,updated_at=$1,updated_by=$2 WHERE id=$3', [stamp, LOCAL_USER.id, r.id]);
    await audit(LOCAL_USER.id, 'ARCHIVE', 'work_order', r.id, { workKey: req.params.key });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/audit', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id,action,entity_type,entity_id,created_at,user_id
      FROM audit_log ORDER BY created_at DESC LIMIT 500`);
    res.json({ audit: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.use(express.static(path.join(ROOT, 'public')));
app.get('/{*splat}', (req, res) => res.sendFile(path.join(ROOT, 'public', 'app.html')));

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`Work Order Desk running on port ${PORT}`));
}).catch(err => {
  console.error('Database initialization failed:', err);
  process.exit(1);
});
