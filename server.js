require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// Web Push (optional: the server still runs if the package / keys are missing)
let webpush = null;
try {
  webpush = require('web-push');
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(
      process.env.VAPID_SUBJECT || 'mailto:admin@example.com',
      process.env.VAPID_PUBLIC_KEY,
      process.env.VAPID_PRIVATE_KEY
    );
  } else {
    console.warn('⚠️ VAPID keys are not set: push notifications are disabled.');
    webpush = null;
  }
} catch (e) {
  console.warn('⚠️ web-push is not installed: push notifications are disabled.');
  webpush = null;
}

const app = express();
const PORT = process.env.PORT || 5000;
const IS_VERCEL = !!process.env.VERCEL;

// ==========================================
// Keep the server alive on unexpected errors
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
  const pass = process.env.ADMIN_PASSWORD;
  if (!pass) {
    return res.status(500).json({ error: 'ADMIN_PASSWORD is not set on the server' });
  }
  const b64 = (req.headers.authorization || '').split(' ')[1] || '';
  const decoded = Buffer.from(b64, 'base64').toString();
  const idx = decoded.indexOf(':');
  const given = idx >= 0 ? decoded.slice(idx + 1) : '';
  if (given && safeEqual(given, pass)) return next();
  res.status(401).json({ error: 'Authentication required' });
}

// Protect admin API routes only; static pages stay public (the page shows its own login form)
app.use('/api/admin', adminAuth);

// ==========================================
// Static files
// ==========================================
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// PostgreSQL (Neon)
// ==========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Required for Neon
  max: IS_VERCEL ? 1 : 5,             // serverless: keep connections low
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

let dbReady = null;
function initDatabase() {
  if (dbReady) return dbReady;
  dbReady = (async () => {
    const client = await pool.connect();
    try {
      console.log('✅ Connected to Neon PostgreSQL database.');

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

      await client.query(`
        CREATE TABLE IF NOT EXISTS app_settings (
          key TEXT PRIMARY KEY,
          value JSONB NOT NULL
        )
      `);

      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT');

      await client.query(`
        CREATE TABLE IF NOT EXISTS push_subscriptions (
          endpoint TEXT PRIMARY KEY,
          user_id UUID NOT NULL,
          subscription JSONB NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now()
        )
      `);
      await client.query(
        'CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions (user_id)'
      );
      console.log('✅ Database schema verified.');
    } finally {
      client.release();
    }
  })().catch((err) => {
    console.error('❌ Error initializing database:', err.message);
    dbReady = null; // allow retry on next request
  });
  return dbReady;
}
initDatabase();

// ==========================================
// HEALTH
// ==========================================
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    env: {
      ADMIN_PASSWORD: !!process.env.ADMIN_PASSWORD,
      DATABASE_URL: !!process.env.DATABASE_URL,
      JWT_SECRET: !!process.env.JWT_SECRET
    }
  });
});

// ==========================================
// BANK DETAILS & APP SETTINGS
// ==========================================
app.get('/api/admin/settings', async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM app_settings WHERE key = 'bank_details'");
    if (result.rows.length === 0) return res.json({});
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
// PUBLIC API
// ==========================================
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

// ==========================================
// ADMIN: STAFF
// ==========================================
app.get('/api/admin/staff', async (req, res) => {
  try {
    // "name" is returned as an alias of full_name so both field names work in the admin page
    const result = await pool.query(
      `SELECT id, full_name, full_name AS name, phone, role::text AS role, photo_url
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
  const fullName = String(b.full_name || b.name || '').trim();
  const phone = String(b.phone || '').trim();
  const password = String(b.password || '');

  // accept "photo" or "photo_url"; ignore the 1x1 placeholder gif the admin page may send
  let photo = b.photo || b.photo_url || null;
  if (photo && String(photo).startsWith('data:image/gif')) photo = null;
  photo = photo ? String(photo) : null;

  if (!STAFF_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (fullName.length < 2 || fullName.length > 100) return res.status(400).json({ error: 'Invalid name' });
  if (!/^\+?\d{9,15}$/.test(phone)) return res.status(400).json({ error: 'Invalid phone' });
  if (password.length < 8 || Buffer.byteLength(password) > 72) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (photo && (!/^data:image\/(jpeg|png|webp);base64,/.test(photo) || photo.length > 400000)) {
    return res.status(400).json({ error: 'Invalid photo (jpeg/png/webp, max ~300KB)' });
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
       RETURNING id, full_name, full_name AS name, phone, role::text AS role, photo_url`,
      [fullName, phone, role, hash, photo]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating staff:', error);
    const code = error.code === '22P02' ? 400 : 500;
    res.status(code).json({ error: 'Could not create the account', detail: error.message });
  }
});

app.delete('/api/admin/staff/:id', async (req, res) => {
  const { id } = req.params;
  if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid id' });

  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    // detach from bookings first so the foreign keys don't block the delete
    await db.query('UPDATE bookings SET therapist_id = NULL WHERE therapist_id = $1', [id]);
    await db.query('UPDATE bookings SET driver_id = NULL WHERE driver_id = $1', [id]);
    const del = await db.query(
      `DELETE FROM users WHERE id = $1 AND role::text IN ('therapist', 'driver')`,
      [id]
    );
    await db.query('COMMIT');
    if (del.rowCount === 0) return res.status(404).json({ error: 'Account not found' });
    res.json({ success: true });
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('❌ Error deleting staff:', error);
    res.status(500).json({ error: 'Could not delete the account', detail: error.message });
  } finally {
    db.release();
  }
});

// ==========================================
// ADMIN: BOOKINGS
// ==========================================
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

async function updateBooking(req, res) {
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

    // Push to the assigned staff phones (new assignment, or status change on their booking)
    const pushJobs = [];
    [[therapistId, old.therapist_id], [driverId, old.driver_id]].forEach(([sid, oldSid]) => {
      if (!sid) return;
      if (sid !== oldSid) pushJobs.push(pushBookingToStaff(id, sid, '📌 حجز جديد معيّن لك', db));
      else if (newStatus !== old.status) pushJobs.push(pushBookingToStaff(id, sid, '🔄 تحديث على حجزك', db));
    });
    await Promise.all(pushJobs);

    res.json({ success: true, notified, message: lines.join(' • ') });
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('❌ Error updating booking:', error);
    const code = error.code === '22P02' ? 400 : 500;
    res.status(code).json({ success: false, error: 'Could not update the booking', detail: error.message });
  } finally {
    db.release();
  }
}

// Both URLs work: the admin page uses PUT /bookings/:id, older code used /bookings/:id/assign
app.put('/api/admin/bookings/:id', updateBooking);
app.put('/api/admin/bookings/:id/assign', updateBooking);

// ==========================================
// STAFF PORTAL & LOGIN
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

    // When the driver arrives, tell the therapist it's time to start
    if (next === 'arrived') {
      const t = await db.query('SELECT therapist_id FROM bookings WHERE id = $1', [id]).catch(() => null);
      const tid = t && t.rows[0] && t.rows[0].therapist_id;
      if (tid) await pushBookingToStaff(id, tid, '🚗 وصل السائق، جهّزي الجلسة', db);
    }

    res.json({ success: true, status: next });
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('❌ Error updating staff booking:', error);
    res.status(500).json({ error: 'Could not update the booking' });
  } finally {
    db.release();
  }
});

// ==========================================
// PUSH NOTIFICATIONS (staff phones)
// ==========================================
const STATUS_AR = {
  pending: 'قيد الانتظار',
  assigned: 'تم التعيين',
  on_the_way: 'في الطريق',
  arrived: 'وصل السائق',
  in_progress: 'قيد التنفيذ',
  completed: 'مكتمل',
  cancelled: 'ملغى'
};

// The booking page stores the address as "text | map link": split them
function splitAddr(address, notes) {
  const urlRe = /https?:\/\/[^\s|]+/;
  const m = String(address || '').match(urlRe) || String(notes || '').match(urlRe);
  return {
    text: String(address || '').replace(/\s*\|?\s*https?:\/\/[^\s|]+/, '').trim(),
    link: m ? m[0] : ''
  };
}

// q = pool or an already-checked-out client (important on Vercel where the pool has 1 connection)
async function sendPush(staffId, payload, q = pool) {
  if (!webpush || !staffId) return;
  try {
    const subs = await q.query('SELECT endpoint, subscription FROM push_subscriptions WHERE user_id = $1', [staffId]);
    const body = JSON.stringify(payload);
    await Promise.all(subs.rows.map(async (row) => {
      try {
        await webpush.sendNotification(row.subscription, body, { TTL: 3600, urgency: 'high' });
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) {
          await q.query('DELETE FROM push_subscriptions WHERE endpoint = $1', [row.endpoint]).catch(() => {});
        } else {
          console.error('⚠️ push send failed:', e.statusCode || '', e.message);
        }
      }
    }));
  } catch (e) {
    console.error('⚠️ push error:', e.message);
  }
}

async function pushBookingToStaff(bookingId, staffId, title, q = pool) {
  if (!webpush || !staffId) return;
  try {
    const r = await q.query(
      `SELECT b.id, u.full_name AS client_name, u.phone AS client_phone, s.title AS service_title,
              to_char(b.booking_date, 'YYYY-MM-DD') AS booking_date,
              to_char(b.booking_time, 'HH24:MI') AS booking_time,
              b.location_address, b.notes, b.status::text AS status
       FROM bookings b
       LEFT JOIN users u ON u.id = b.client_id
       LEFT JOIN services s ON s.id = b.service_id
       WHERE b.id = $1`,
      [bookingId]
    );
    if (!r.rows.length) return;
    const b = r.rows[0];
    const a = splitAddr(b.location_address, b.notes);
    await sendPush(staffId, {
      title,
      body:
        `👤 ${b.client_name || 'عميل'}\n` +
        `💆 ${b.service_title || 'خدمة مساج'}\n` +
        `🕒 ${b.booking_date} ${b.booking_time}\n` +
        `📍 ${a.text || 'غير محدد'}\n` +
        `الحالة: ${STATUS_AR[b.status] || b.status}`,
      tag: 'booking-' + bookingId,
      url: '/staff'
    }, q);
  } catch (e) {
    console.error('⚠️ pushBookingToStaff error:', e.message);
  }
}

app.get('/api/staff/push/key', (req, res) => {
  res.json({ key: webpush ? process.env.VAPID_PUBLIC_KEY : '' });
});

app.post('/api/staff/push/subscribe', requireStaff, async (req, res) => {
  const sub = req.body && req.body.subscription;
  if (!sub || !sub.endpoint || !sub.keys) return res.status(400).json({ error: 'Invalid subscription' });
  try {
    await pool.query(
      `INSERT INTO push_subscriptions (endpoint, user_id, subscription)
       VALUES ($1, $2, $3::jsonb)
       ON CONFLICT (endpoint) DO UPDATE SET user_id = $2, subscription = $3::jsonb`,
      [sub.endpoint, req.staff.id, JSON.stringify(sub)]
    );
    res.json({ success: true });
  } catch (e) {
    console.error('❌ subscribe error:', e);
    res.status(500).json({ error: 'Could not save subscription' });
  }
});

app.post('/api/staff/push/unsubscribe', requireStaff, async (req, res) => {
  const endpoint = req.body && req.body.endpoint;
  if (endpoint) await pool.query('DELETE FROM push_subscriptions WHERE endpoint = $1', [endpoint]).catch(() => {});
  res.json({ success: true });
});

app.post('/api/staff/push/test', requireStaff, async (req, res) => {
  if (!webpush) return res.status(503).json({ error: 'Push is not configured on the server' });
  await sendPush(req.staff.id, {
    title: '✅ الإشعارات تعمل',
    body: 'ستصلك هنا تفاصيل الحجوزات الجديدة وتحديثاتها.',
    tag: 'test',
    url: '/staff'
  });
  res.json({ success: true });
});

// ==========================================
// CLIENT SYNC
// ==========================================
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
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get(['/admin', '/admin/'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get(['/staff', '/staff/'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'staff.html'));
});

// Unknown /api routes get JSON 404 instead of the home page
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==========================================
// START
// Local / Fly.io / Docker: listen on a port.
// Vercel: export the app (no listen).
// ==========================================
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server listening on port ${PORT}`);
  });
}

module.exports = app;