require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

// ==========================================
// Keep server alive on unexpected errors
// ==========================================
process.on('unhandledRejection', (e) => console.error('⚠️ unhandledRejection:', e && e.message ? e.message : e));
process.on('uncaughtException', (e) => console.error('⚠️ uncaughtException:', e && e.message ? e.message : e));

// Middleware
app.use(cors());
app.use(express.json({ limit: '2mb' })); // staff photos arrive as small base64 images

// ==========================================
// Admin protection (HTTP Basic Auth for API ONLY)
// ==========================================
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function adminAuth(req, res, next) {
  const pass = (process.env.ADMIN_PASSWORD || '').trim();
  if (!pass) {
    return res.status(500).json({ error: 'ADMIN_PASSWORD is not set on the server' });
  }
  const b64 = (req.headers.authorization || '').split(' ')[1] || '';
  const decoded = Buffer.from(b64, 'base64').toString();
  const idx = decoded.indexOf(':');
  const given = (idx >= 0 ? decoded.slice(idx + 1) : '').trim();
  if (given && safeEqual(given, pass)) return next();
  
  res.status(401).json({ error: 'Authentication required' });
}

// Protect admin API routes
app.use('/api/admin', adminAuth);

// ==========================================
// SERVE STATIC FILES FROM PUBLIC DIRECTORY
// ==========================================
app.use(express.static(path.join(__dirname, 'public')));

// PostgreSQL connection setup using process.env.DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Neon PostgreSQL
  },
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000,
  keepAlive: true
});

pool.on('error', (err) => {
  console.error('⚠️ Pool error (ignored):', err.message);
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PAYMENT_STATUSES = ['unpaid', 'paid', 'refunded'];
const STAFF_ROLES = ['therapist', 'driver'];

const STATUS_MESSAGES = {
  pending: 'حجزك قيد المراجعة',
  assigned: 'تم تأكيد حجزك وتجهيز فريق الجلسة',
  on_the_way: 'فريقنا في الطريق إليك الآن',
  arrived: 'وصل الفريق إلى موقعك',
  in_progress: 'بدأت جلستك، نتمنى لك الراحة والاسترخاء',
  completed: 'اكتملت جلستك، شكراً لثقتك بنا',
  cancelled: 'تم إلغاء حجزك'
};
const PAYMENT_MESSAGES = {
  unpaid: 'حالة الدفع: غير مدفوع',
  paid: 'تم تأكيد استلام الدفع، شكراً لك',
  refunded: 'تم استرجاع المبلغ'
};

async function initDatabase() {
  const client = await pool.connect();
  try {
    console.log('✅ Connected to Neon PostgreSQL database.');
    
    // Notifications table
    await client.query(`
      CREATE TABLE IF NOT EXISTS booking_notifications (
        id SERIAL PRIMARY KEY,
        booking_id UUID NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now()
      )
    `);
    await client.query(
      'CREATE INDEX IF NOT EXISTS idx_booking_notifications_booking ON booking_notifications (booking_id)'
    );

    // App Settings table for bank details
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL
      )
    `);

    // Users staff columns
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT');
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT');
    console.log('✅ Database schema verified.');
  } finally {
    client.release();
  }
}
initDatabase().catch((err) => console.error('❌ Error initializing database:', err.message));

// ==========================================
// BANK DETAILS & APP SETTINGS ENDPOINTS
// ==========================================

app.get('/api/admin/settings', async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM app_settings WHERE key = 'bank_details'");
    if (result.rows.length === 0) {
      return res.json({});
    }
    res.json(result.rows[0].value);
  } catch (error) {
    console.error('❌ Error fetching settings:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/settings', async (req, res) => {
  try {
    const bankDetails = req.body || {};
    await pool.query(
      `INSERT INTO app_settings (key, value)
       VALUES ('bank_details', $1::jsonb)
       ON CONFLICT (key) DO UPDATE SET value = $1::jsonb`,
      [JSON.stringify(bankDetails)]
    );
    res.json({ success: true, message: 'Bank settings saved successfully' });
  } catch (error) {
    console.error('❌ Error saving settings:', error);
    res.status(500).json({ error: 'Could not save bank settings' });
  }
});

// ==========================================
// CORE API ENDPOINTS
// ==========================================

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/services', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, title, duration_minutes, price FROM services ORDER BY id'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching services:', error);
    res.status(500).json({ error: 'Database error while fetching services', detail: error.message });
  }
});

app.post('/api/bookings', async (req, res) => {
  const body = req.body || {};
  const client_name = body.full_name || body.client_name;
  const client_phone = body.phone || body.client_phone;
  const { service_id, booking_date, booking_time, location_address, latitude, longitude, notes, people_count } = body;

  if (!client_name || !client_phone || !service_id || !booking_date || !booking_time || !location_address) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  const db = await pool.connect();
  try {
    await db.query('BEGIN');

    const existing = await db.query(
      `SELECT id FROM users
       WHERE phone = $1 AND COALESCE(role::text, '') NOT IN ('therapist', 'driver')
       LIMIT 1`,
      [client_phone]
    );
    let clientId;
    if (existing.rows.length > 0) {
      clientId = existing.rows[0].id;
    } else {
      const created = await db.query(
        'INSERT INTO users (full_name, phone) VALUES ($1, $2) RETURNING id',
        [client_name, client_phone]
      );
      clientId = created.rows[0].id;
    }

    let fullNotes = notes || '';
    if (latitude && longitude) {
      fullNotes += (fullNotes ? '\n' : '') + `https://www.google.com/maps?q=${latitude},${longitude}`;
    }

    const result = await db.query(
      `INSERT INTO bookings
        (client_id, service_id, people_count, booking_date, booking_time, location_address, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, status::text AS status`,
      [
        clientId,
        service_id,
        parseInt(people_count, 10) || 1,
        booking_date,
        booking_time,
        location_address,
        fullNotes
      ]
    );

    await db.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Booking created successfully',
      booking: result.rows[0]
    });
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('❌ Error creating booking:', error);
    res.status(500).json({
      success: false,
      error: 'Database error while creating booking',
      detail: error.message
    });
  } finally {
    db.release();
  }
});

app.get('/api/admin/staff', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, phone, role::text AS role, photo_url
       FROM users
       WHERE role::text IN ('therapist', 'driver')
       ORDER BY full_name`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching staff:', error);
    res.status(500).json({ error: 'Database error while fetching staff', detail: error.message });
  }
});

app.post('/api/admin/staff', async (req, res) => {
  const b = req.body || {};
  const role = String(b.role || '');
  const fullName = String(b.full_name || '').trim();
  const phone = String(b.phone || '').trim();
  const password = String(b.password || '');
  const photo = b.photo ? String(b.photo) : null;

  if (!STAFF_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (fullName.length < 2 || fullName.length > 100) return res.status(400).json({ error: 'Invalid name' });
  if (!/^\+?\d{9,15}$/.test(phone)) return res.status(400).json({ error: 'Invalid phone' });
  if (password.length < 8 || Buffer.byteLength(password) > 72) return res.status(400).json({ error: 'Invalid password' });
  if (photo && (!/^data:image\/(jpeg|png|webp);base64,/.test(photo) || photo.length > 400000)) {
    return res.status(400).json({ error: 'Invalid photo' });
  }

  try {
    const dup = await pool.query(
      `SELECT 1 FROM users WHERE phone = $1 AND role::text IN ('therapist', 'driver') LIMIT 1`,
      [phone]
    );
    if (dup.rows.length > 0) return res.status(409).json({ error: 'Phone already used by a staff member' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (full_name, phone, role, password_hash, photo_url)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, full_name, phone, role::text AS role, photo_url`,
      [fullName, phone, role, hash, photo]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating staff:', error);
    const code = error.code === '22P02' ? 400 : 500;
    res.status(code).json({ error: 'Could not create the account', detail: error.message });
  }
});

app.get('/api/admin/bookings', async (req, res) => {
  try {
    const query = `
      SELECT
        b.id,
        u.full_name AS client_name,
        u.phone AS client_phone,
        s.title AS service_title,
        (s.price * COALESCE(b.people_count, 1)) AS service_price,
        to_char(b.booking_date, 'YYYY-MM-DD') AS booking_date,
        to_char(b.booking_time, 'HH24:MI') AS booking_time,
        b.location_address,
        b.notes,
        b.people_count,
        b.therapist_id,
        t.full_name AS therapist_name,
        b.driver_id,
        d.full_name AS driver_name,
        b.status::text AS status,
        b.payment_status::text AS payment_status,
        b.created_at
      FROM bookings b
      LEFT JOIN users u ON u.id = b.client_id
      LEFT JOIN services s ON s.id = b.service_id
      LEFT JOIN users t ON t.id = b.therapist_id
      LEFT JOIN users d ON d.id = b.driver_id
      ORDER BY b.created_at DESC;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching admin bookings:', error);
    res.status(500).json({ error: 'Database error while fetching bookings', detail: error.message });
  }
});

app.put('/api/admin/bookings/:id/assign', async (req, res) => {
  const { id } = req.params;
  const body = req.body || {};
  const therapistId = body.therapist_id ? String(body.therapist_id).toLowerCase() : null;
  const driverId = body.driver_id ? String(body.driver_id).toLowerCase() : null;

  if (!UUID_RE.test(id)) {
    return res.status(400).json({ success: false, error: 'Invalid booking id' });
  }
  if ((therapistId && !UUID_RE.test(therapistId)) || (driverId && !UUID_RE.test(driverId))) {
    return res.status(400).json({ success: false, error: 'Invalid staff id' });
  }
  if (body.payment_status && !PAYMENT_STATUSES.includes(body.payment_status)) {
    return res.status(400).json({ success: false, error: 'Invalid payment status' });
  }

  const db = await pool.connect();
  try {
    await db.query('BEGIN');

    const current = await db.query(
      `SELECT therapist_id, driver_id, status::text AS status, payment_status::text AS payment_status
       FROM bookings WHERE id = $1 FOR UPDATE`,
      [id]
    );
    if (current.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }
    const old = current.rows[0];
    const newStatus = body.status || old.status;
    const newPayment = body.payment_status || old.payment_status;

    const staffIds = [therapistId, driverId].filter(Boolean);
    const staffRes = await db.query(
      'SELECT id, full_name, role::text AS role FROM users WHERE id = ANY($1::uuid[])',
      [staffIds]
    );
    const staff = {};
    staffRes.rows.forEach((p) => { staff[p.id] = p; });
    if (therapistId && (!staff[therapistId] || staff[therapistId].role !== 'therapist')) {
      await db.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'The selected therapist is not valid' });
    }
    if (driverId && (!staff[driverId] || staff[driverId].role !== 'driver')) {
      await db.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'The selected driver is not valid' });
    }

    await db.query(
      `UPDATE bookings
       SET therapist_id = $1, driver_id = $2,
           status = $3::booking_status, payment_status = $4::payment_status
       WHERE id = $5`,
      [therapistId, driverId, newStatus, newPayment, id]
    );

    const lines = [];
    if (therapistId && therapistId !== old.therapist_id) {
      lines.push(`تم تعيين المعالجة ${staff[therapistId].full_name} لجلستك`);
    }
    if (driverId && driverId !== old.driver_id) {
      lines.push(`تم تعيين السائق ${staff[driverId].full_name}`);
    }
    if (newStatus !== old.status) {
      lines.push(STATUS_MESSAGES[newStatus] || 'تم تحديث حالة حجزك');
    }
    if (newPayment !== old.payment_status) {
      lines.push(PAYMENT_MESSAGES[newPayment] || 'تم تحديث حالة الدفع');
    }

    let notified = false;
    if (lines.length > 0) {
      await db.query(
        'INSERT INTO booking_notifications (booking_id, title, message) VALUES ($1, $2, $3)',
        [id, `تحديث على حجزك #${id.slice(0, 8).toUpperCase()}`, lines.join('\n')]
      );
      notified = true;
    }

    await db.query('COMMIT');
    res.json({ success: true, notified, message: lines.join(' • ') });
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('❌ Error assigning booking:', error);
    const code = error.code === '22P02' ? 400 : 500;
    res.status(code).json({ success: false, error: 'Could not update the booking', detail: error.message });
  } finally {
    db.release();
  }
});

// ==========================================
// STAFF PORTAL & LOGIN SYSTEM
// ==========================================

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);
const loginFails = new Map();

const STAFF_FLOW = {
  driver:    { assigned: 'on_the_way', on_the_way: 'arrived' },
  therapist: { arrived: 'in_progress', in_progress: 'completed' }
};

function requireStaff(req, res, next) {
  try {
    if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not set');
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!STAFF_ROLES.includes(payload.role)) throw new Error('bad role');
    req.staff = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

app.post('/api/staff/login', async (req, res) => {
  try {
    if (!process.env.JWT_SECRET) return res.status(500).json({ error: 'JWT_SECRET is not set on the server' });

    const phone = String((req.body && req.body.phone) || '').trim();
    const password = String((req.body && req.body.password) || '');
    const key = `${req.ip}|${phone}`;
    const fails = loginFails.get(key);
    if (fails && fails.n >= 5 && Date.now() < fails.until) {
      return res.status(429).json({ error: 'Too many attempts, try again later' });
    }

    const result = await pool.query(
      `SELECT id, full_name, role::text AS role, photo_url, password_hash
       FROM users
       WHERE phone = $1 AND role::text IN ('therapist', 'driver') AND password_hash IS NOT NULL
       LIMIT 1`,
      [phone]
    );
    const u = result.rows[0];
    const ok = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH);

    if (!u || !ok) {
      loginFails.set(key, { n: (fails ? fails.n : 0) + 1, until: Date.now() + 10 * 60 * 1000 });
      return res.status(401).json({ error: 'wrong credentials' });
    }
    loginFails.delete(key);

    const token = jwt.sign({ id: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { id: u.id, full_name: u.full_name, role: u.role, photo_url: u.photo_url } });
  } catch (error) {
    console.error('❌ Staff login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/staff/me/bookings', requireStaff, async (req, res) => {
  try {
    const col = req.staff.role === 'therapist' ? 'therapist_id' : 'driver_id';
    const result = await pool.query(
      `SELECT
          b.id,
          u.full_name AS client_name,
          u.phone AS client_phone,
          s.title AS service_title,
          s.duration_minutes,
          to_char(b.booking_date, 'YYYY-MM-DD') AS booking_date,
          to_char(b.booking_time, 'HH24:MI') AS booking_time,
          b.location_address,
          b.notes,
          b.people_count,
          b.status::text AS status
       FROM bookings b
       LEFT JOIN users u ON u.id = b.client_id
       LEFT JOIN services s ON s.id = b.service_id
       WHERE b.${col} = $1 AND b.status::text <> 'cancelled'
       ORDER BY b.booking_date DESC, b.booking_time DESC
       LIMIT 100`,
      [req.staff.id]
    );
    res.json(result.rows.map((r) => ({ ...r, next_status: (STAFF_FLOW[req.staff.role] || {})[r.status] || null })));
  } catch (error) {
    console.error('❌ Error fetching staff bookings:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/staff/me/bookings/:id', requireStaff, async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid booking id' });

  const col = req.staff.role === 'therapist' ? 'therapist_id' : 'driver_id';
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    const cur = await db.query(
      `SELECT status::text AS status FROM bookings WHERE id = $1 AND ${col} = $2 FOR UPDATE`,
      [id, req.staff.id]
    );
    if (cur.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.status(404).json({ error: 'Booking not found' });
    }

    const next = (STAFF_FLOW[req.staff.role] || {})[cur.rows[0].status];
    if (!next || next !== (req.body && req.body.status)) {
      await db.query('ROLLBACK');
      return res.status(400).json({ error: 'This step is not allowed now' });
    }

    await db.query('UPDATE bookings SET status = $1::booking_status WHERE id = $2', [next, id]);
    await db.query(
      'INSERT INTO booking_notifications (booking_id, title, message) VALUES ($1, $2, $3)',
      [id, `تحديث على حجزك #${id.slice(0, 8).toUpperCase()}`, STATUS_MESSAGES[next] || 'تم تحديث حالة حجزك']
    );
    await db.query('COMMIT');
    res.json({ success: true, status: next });
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('❌ Error updating staff booking:', error);
    res.status(500).json({ error: 'Could not update the booking' });
  } finally {
    db.release();
  }
});

app.post('/api/client/sync', async (req, res) => {
  try {
    const raw = Array.isArray(req.body && req.body.ids) ? req.body.ids : [];
    const ids = raw.filter((x) => typeof x === 'string' && UUID_RE.test(x)).slice(0, 20);
    if (ids.length === 0) {
      return res.json({ success: true, bookings: [], notifications: [] });
    }

    const bookings = await pool.query(
      `SELECT b.id, b.status::text AS status, b.payment_status::text AS payment_status,
              t.full_name AS therapist_name, d.full_name AS driver_name
       FROM bookings b
       LEFT JOIN users t ON t.id = b.therapist_id
       LEFT JOIN users d ON d.id = b.driver_id
       WHERE b.id = ANY($1::uuid[])`,
      [ids]
    );
    const notifications = await pool.query(
      `SELECT id, booking_id, title, message, created_at
       FROM booking_notifications
       WHERE booking_id = ANY($1::uuid[])
       ORDER BY id DESC LIMIT 100`,
      [ids]
    );

    res.json({ success: true, bookings: bookings.rows, notifications: notifications.rows });
  } catch (error) {
    console.error('❌ Error syncing client data:', error);
    res.status(500).json({ success: false, error: 'Could not load updates', detail: error.message });
  }
});

// ==========================================
// FRONTEND PAGE ROUTES
// ==========================================

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Export app for Vercel Serverless functions
module.exports = app;