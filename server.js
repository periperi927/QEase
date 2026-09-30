const express = require('express');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { initDatabase, query, run } = require('./config/db');

const app = express();
const PORT = process.env.PORT || 3000;
if (process.env.RENDER_EXTERNAL_URL) {
  app.set('trust proxy', 1);
}
const COOKIE_NAME = 'qease_session';
const SESSIONS = new Map();
const EVENT_CLIENTS = new Set();
const adminUsername = process.env.QEASE_ADMIN_USERNAME || 'admin';
const ADMIN_USERS = new Map([
  [adminUsername.toLowerCase(), {
    username: adminUsername,
    passwordHash: null,
    passwordSalt: crypto.randomBytes(16),
    password: process.env.QEASE_ADMIN_PASSWORD || '',
    role: 'admin',
  }],
]);
const LOGIN_ATTEMPTS = new Map();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_FAILURES = 5;

function generateSessionToken() {
  return crypto.randomBytes(24).toString('hex');
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64);
}

function verifyPassword(password, salt, expectedHash) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, expectedHash.length, (error, hash) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(crypto.timingSafeEqual(hash, expectedHash));
    });
  });
}

for (const user of ADMIN_USERS.values()) {
  if (user.password.length < 12) {
    throw new Error('QEASE_ADMIN_PASSWORD must be set to at least 12 characters.');
  }

  user.passwordHash = hashPassword(user.password, user.passwordSalt);
  delete user.password;
}

if (process.env.QEASE_STAFF_PASSWORD) {
  const staffPassword = process.env.QEASE_STAFF_PASSWORD;
  if (staffPassword.length < 12) {
    throw new Error('QEASE_STAFF_PASSWORD must be at least 12 characters.');
  }

  const staff = {
    username: process.env.QEASE_STAFF_USERNAME || 'staff',
    passwordSalt: crypto.randomBytes(16),
    role: 'staff',
  };
  staff.passwordHash = hashPassword(staffPassword, staff.passwordSalt);
  ADMIN_USERS.set(staff.username.toLowerCase(), staff);
}

const publicBaseUrlValue = process.env.QEASE_PUBLIC_BASE_URL || process.env.RENDER_EXTERNAL_URL;
const configuredPublicBaseUrl = publicBaseUrlValue ? new URL(publicBaseUrlValue) : null;

if (configuredPublicBaseUrl && !['http:', 'https:'].includes(configuredPublicBaseUrl.protocol)) {
  throw new Error('QEASE_PUBLIC_BASE_URL must use HTTP or HTTPS.');
}

if (configuredPublicBaseUrl && (
  configuredPublicBaseUrl.username ||
  configuredPublicBaseUrl.password ||
  configuredPublicBaseUrl.search ||
  configuredPublicBaseUrl.hash
)) {
  throw new Error('QEASE_PUBLIC_BASE_URL must not contain credentials, a query, or a fragment.');
}

if (process.env.NODE_ENV === 'production' && !configuredPublicBaseUrl) {
  throw new Error('QEASE_PUBLIC_BASE_URL must be set in production so ticket QR codes are reachable.');
}

function getTrackingUrl(req, ticketCode) {
  const baseUrl = configuredPublicBaseUrl || new URL(`${req.protocol}://${req.get('host')}`);
  const trackingUrl = new URL('track.html', baseUrl.toString().endsWith('/') ? baseUrl : `${baseUrl}/`);
  trackingUrl.searchParams.set('ticket', ticketCode);
  return trackingUrl;
}

function publishQueueUpdate() {
  const message = `event: queue:update\ndata: ${JSON.stringify({ updatedAt: new Date().toISOString() })}\n\n`;
  for (const client of EVENT_CLIENTS) {
    client.write(message);
  }
}

function getLoginAttemptKey(req) {
  return req.ip;
}

function getActiveLoginAttempt(key, now = Date.now()) {
  for (const [attemptKey, attempt] of LOGIN_ATTEMPTS) {
    if (attempt.resetAt <= now) {
      LOGIN_ATTEMPTS.delete(attemptKey);
    }
  }

  const attempt = LOGIN_ATTEMPTS.get(key);
  if (!attempt || attempt.resetAt <= now) {
    LOGIN_ATTEMPTS.delete(key);
    return null;
  }

  return attempt;
}

function getSessionUser(req) {
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(new RegExp(`(?:^|; )${COOKIE_NAME}=([^;]+)`));

  if (!match) {
    return null;
  }

  let token;
  try {
    token = decodeURIComponent(match[1]);
  } catch {
    return null;
  }

  const session = SESSIONS.get(token);
  if (!session) {
    return null;
  }
  if (session.expiresAt <= Date.now()) {
    SESSIONS.delete(token);
    return null;
  }

  return session.user;
}

function requireAdmin(req, res, next) {
  const user = getSessionUser(req);

  if (!user) {
    return res.status(401).json({ error: 'Unauthorized. Please log in to continue.' });
  }

  req.user = user;
  next();
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/api/admin/session', (req, res) => {
  const user = getSessionUser(req);

  if (!user) {
    return res.status(401).json({ error: 'Not logged in.' });
  }

  res.json({ user });
});

app.post('/api/admin/login', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const user = ADMIN_USERS.get(username);
  if (username.length > 128 || password.length > 1024) {
    return res.status(400).json({ error: 'Username or password is too long.' });
  }

  const attemptKey = getLoginAttemptKey(req);
  const attempt = getActiveLoginAttempt(attemptKey);

  if (attempt && attempt.count >= MAX_LOGIN_FAILURES) {
    res.set('Retry-After', String(Math.ceil((attempt.resetAt - Date.now()) / 1000)));
    return res.status(429).json({ error: 'Too many failed login attempts. Please try again later.' });
  }

  let isValidPassword = false;
  try {
    isValidPassword = await verifyPassword(
      password,
      user ? user.passwordSalt : Buffer.alloc(16),
      user ? user.passwordHash : Buffer.alloc(64)
    );
  } catch (error) {
    return res.status(500).json({ error: `Unable to verify login credentials: ${error.message}` });
  }

  if (!isValidPassword) {
    const activeAttempt = attempt || { count: 0, resetAt: Date.now() + LOGIN_WINDOW_MS };
    activeAttempt.count += 1;
    LOGIN_ATTEMPTS.set(attemptKey, activeAttempt);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  LOGIN_ATTEMPTS.delete(attemptKey);
  for (const [key, session] of SESSIONS) {
    if (session.expiresAt <= Date.now()) {
      SESSIONS.delete(key);
    }
  }
  const token = generateSessionToken();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const sessionUser = { username: user.username, role: user.role };
  SESSIONS.set(token, { user: sessionUser, expiresAt });

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: SESSION_TTL_MS,
  });

  res.json({ ok: true, user: sessionUser });
});

app.post('/api/admin/logout', (req, res) => {
  const token = (req.headers.cookie || '').match(new RegExp(`(?:^|; )${COOKIE_NAME}=([^;]+)`));

  if (token) {
    SESSIONS.delete(decodeURIComponent(token[1]));
  }

  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });
  res.json({ ok: true });
});

app.get('/api/events', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write('retry: 3000\n\n');
  EVENT_CLIENTS.add(res);

  const heartbeat = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 25000);

  res.on('close', () => {
    clearInterval(heartbeat);
    EVENT_CLIENTS.delete(res);
  });

  res.write(`event: queue:update\ndata: ${JSON.stringify({ updatedAt: new Date().toISOString() })}\n\n`);
});

app.get('/api/analytics/today', requireAdmin, async (req, res) => {
  try {
    const [analytics] = await query(`
      SELECT
        (SELECT COUNT(*)
         FROM tickets
         WHERE date(created_at, 'localtime') = date('now', 'localtime')) AS total_tickets_today,
        (SELECT COUNT(*)
         FROM tickets
         WHERE status = 'served'
           AND served_at IS NOT NULL
           AND date(served_at, 'localtime') = date('now', 'localtime')) AS served_tickets_today,
        (SELECT AVG((julianday(called_at) - julianday(created_at)) * 24 * 60)
         FROM tickets
         WHERE called_at IS NOT NULL
           AND date(called_at, 'localtime') = date('now', 'localtime')) AS average_wait_minutes
    `);

    res.json({
      totalTicketsToday: Number(analytics.total_tickets_today || 0),
      servedTicketsToday: Number(analytics.served_tickets_today || 0),
      averageWaitMinutes: analytics.average_wait_minutes == null
        ? null
        : Number(analytics.average_wait_minutes),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/peak-hours', requireAdmin, async (req, res) => {
  try {
    const peakHours = await query(`
      SELECT strftime('%H:00', created_at, 'localtime') AS hour, COUNT(*) AS tickets
      FROM tickets
      WHERE date(created_at, 'localtime') = date('now', 'localtime')
      GROUP BY strftime('%H', created_at, 'localtime')
      ORDER BY tickets DESC, hour ASC
      LIMIT 5
    `);

    res.json({ peakHours: peakHours.map((entry) => ({
      hour: entry.hour,
      tickets: Number(entry.tickets),
    })) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/queues', async (req, res) => {
  try {
    const queues = await query('SELECT * FROM queues ORDER BY id');
    res.json(queues);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/queues', requireAdmin, async (req, res) => {
  const { name, prefix } = req.body || {};
  const queueName = String(name || '').trim();
  const queuePrefix = String(prefix || '').trim().toUpperCase();

  if (!queueName || !queuePrefix) {
    return res.status(400).json({ error: 'Queue name and prefix are required.' });
  }

  try {
    const existing = await query('SELECT id FROM queues WHERE LOWER(prefix) = LOWER(?)', [queuePrefix]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'A queue with this prefix already exists.' });
    }

    const result = await run('INSERT INTO queues (name, prefix) VALUES (?, ?)', [queueName, queuePrefix]);
    const queue = await query('SELECT * FROM queues WHERE id = ?', [result.id]);
    publishQueueUpdate();
    res.status(201).json(queue[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tickets/issue', requireAdmin, async (req, res) => {
  const queueId = Number(req.body?.queue_id ?? req.body?.queueId);

  if (!Number.isInteger(queueId) || queueId <= 0) {
    return res.status(400).json({ error: 'A valid queue id is required.' });
  }

  try {
    const queueRows = await query('SELECT * FROM queues WHERE id = ?', [queueId]);
    const queue = queueRows[0];

    if (!queue) {
      return res.status(404).json({ error: 'Queue not found.' });
    }

    const [sequence] = await query(`
      INSERT INTO queue_ticket_sequences (queue_id, next_ticket_no)
      SELECT ?, COALESCE(MAX(ticket_no), 0) + 1
      FROM tickets
      WHERE queue_id = ?
      ON CONFLICT(queue_id) DO UPDATE
      SET next_ticket_no = queue_ticket_sequences.next_ticket_no + 1
      RETURNING next_ticket_no
    `, [queueId, queueId]);

    const ticketNo = Number(sequence.next_ticket_no);
    const code = `${queue.prefix}-${ticketNo}`;
    const trackingUrl = getTrackingUrl(req, code);
    const qrCodeDataUrl = await QRCode.toDataURL(trackingUrl.toString(), {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 240,
    });

    const insertResult = await run(
      'INSERT INTO tickets (queue_id, ticket_no, code, status, created_at, updated_at) VALUES (?, ?, ?, ?, datetime("now"), datetime("now"))',
      [queueId, ticketNo, code, 'waiting']
    );

    const tickets = await query('SELECT t.*, q.name AS queue_name, q.prefix FROM tickets t JOIN queues q ON q.id = t.queue_id WHERE t.id = ?', [insertResult.id]);
    res.status(201).json({
      ...tickets[0],
      trackingUrl: trackingUrl.toString(),
      qrCodeDataUrl,
    });
    publishQueueUpdate();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tickets/active', async (req, res) => {
  try {
    const tickets = await query(`
      SELECT t.*, q.name AS queue_name, q.prefix
      FROM tickets t
      JOIN queues q ON q.id = t.queue_id
      WHERE t.status IN ('waiting', 'called', 'serving')
      ORDER BY q.id, t.ticket_no
    `);
    res.json(tickets);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/kiosk/board', async (req, res) => {
  try {
    const nowServing = await query(`
      SELECT t.id, t.code, t.status, t.counter_no, t.updated_at, q.name AS queue_name, q.prefix
      FROM tickets t
      JOIN queues q ON q.id = t.queue_id
      WHERE t.status IN ('called', 'serving')
      ORDER BY q.id, t.counter_no, t.updated_at DESC
    `);
    const nextTickets = await query(`
      SELECT id, code, status, counter_no, created_at, queue_id, queue_name, prefix, queue_position
      FROM (
        SELECT
          t.id,
          t.code,
          t.status,
          t.counter_no,
          t.created_at,
          t.queue_id,
          q.name AS queue_name,
          q.prefix,
          ROW_NUMBER() OVER (PARTITION BY t.queue_id ORDER BY t.ticket_no) AS queue_position
        FROM tickets t
        JOIN queues q ON q.id = t.queue_id
        WHERE t.status = 'waiting'
      )
      WHERE queue_position <= 3
      ORDER BY queue_id, queue_position
    `);

    res.json({ nowServing, nextTickets });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/queues/:id/status', async (req, res) => {
  const queueId = Number(req.params.id);

  if (!Number.isInteger(queueId) || queueId <= 0) {
    return res.status(400).json({ error: 'A valid queue id is required.' });
  }

  try {
    const queue = await query('SELECT * FROM queues WHERE id = ?', [queueId]);

    if (queue.length === 0) {
      return res.status(404).json({ error: 'Queue not found.' });
    }

    const summary = await query(`
      SELECT
        SUM(CASE WHEN status = 'waiting' THEN 1 ELSE 0 END) AS waiting,
        SUM(CASE WHEN status = 'called' THEN 1 ELSE 0 END) AS called,
        SUM(CASE WHEN status = 'serving' THEN 1 ELSE 0 END) AS serving,
        SUM(CASE WHEN status = 'served' THEN 1 ELSE 0 END) AS served,
        SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END) AS skipped,
        MIN(CASE WHEN status = 'waiting' THEN ticket_no END) AS next_ticket_no
      FROM tickets
      WHERE queue_id = ?
    `, [queueId]);

    const nextTicket = await query(`
      SELECT t.*, q.name AS queue_name, q.prefix
      FROM tickets t
      JOIN queues q ON q.id = t.queue_id
      WHERE t.queue_id = ? AND t.status = 'waiting'
      ORDER BY t.ticket_no ASC
      LIMIT 1
    `, [queueId]);

    const currentTicket = await query(`
      SELECT t.*, q.name AS queue_name, q.prefix
      FROM tickets t
      JOIN queues q ON q.id = t.queue_id
      WHERE t.queue_id = ? AND t.status IN ('called', 'serving')
      ORDER BY CASE t.status WHEN 'called' THEN 1 WHEN 'serving' THEN 2 ELSE 3 END, t.updated_at DESC
      LIMIT 1
    `, [queueId]);

    res.json({
      queue: queue[0],
      summary: summary[0],
      nextTicket: nextTicket[0] || null,
      currentTicket: currentTicket[0] || null,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/queues/:id/next', requireAdmin, async (req, res) => {
  const queueId = Number(req.params.id);
  const counterNo = req.body?.counter_no != null ? Number(req.body.counter_no) : null;

  if (!Number.isInteger(queueId) || queueId <= 0) {
    return res.status(400).json({ error: 'A valid queue id is required.' });
  }

  try {
    const queue = await query('SELECT * FROM queues WHERE id = ?', [queueId]);
    if (queue.length === 0) {
      return res.status(404).json({ error: 'Queue not found.' });
    }

    const nextTicket = await query(`
      SELECT t.*, q.name AS queue_name, q.prefix
      FROM tickets t
      JOIN queues q ON q.id = t.queue_id
      WHERE t.queue_id = ? AND t.status = 'waiting'
      ORDER BY t.ticket_no ASC
      LIMIT 1
    `, [queueId]);

    if (nextTicket.length === 0) {
      return res.status(404).json({ error: 'No waiting tickets in this queue.' });
    }

    const ticket = nextTicket[0];
    const safeCounter = Number.isInteger(counterNo) ? counterNo : 1;

    await run(
      'UPDATE tickets SET status = ?, counter_no = ?, called_at = COALESCE(called_at, datetime("now")), updated_at = datetime("now") WHERE id = ?',
      ['called', safeCounter, ticket.id]
    );
    publishQueueUpdate();

    const updated = await query(`
      SELECT t.*, q.name AS queue_name, q.prefix
      FROM tickets t
      JOIN queues q ON q.id = t.queue_id
      WHERE t.id = ?
    `, [ticket.id]);

    res.json(updated[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/queues/:id/reset', requireAdmin, async (req, res) => {
  const queueId = Number(req.params.id);

  if (!Number.isInteger(queueId) || queueId <= 0) {
    return res.status(400).json({ error: 'A valid queue id is required.' });
  }

  try {
    const queue = await query('SELECT * FROM queues WHERE id = ?', [queueId]);
    if (queue.length === 0) {
      return res.status(404).json({ error: 'Queue not found.' });
    }

    await run(
      `UPDATE tickets
       SET status = 'waiting', counter_no = NULL, called_at = NULL, served_at = NULL, updated_at = datetime("now")
       WHERE queue_id = ?`,
      [queueId]
    );
    publishQueueUpdate();

    const resetTickets = await query(
      'SELECT * FROM tickets WHERE queue_id = ? ORDER BY ticket_no ASC',
      [queueId]
    );

    res.json({ message: 'Queue reset successfully.', tickets: resetTickets });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/queues/:id/tickets', requireAdmin, async (req, res) => {
  const queueId = Number(req.params.id);

  if (!Number.isInteger(queueId) || queueId <= 0) {
    return res.status(400).json({ error: 'A valid queue id is required.' });
  }

  try {
    const queue = await query('SELECT * FROM queues WHERE id = ?', [queueId]);
    if (queue.length === 0) {
      return res.status(404).json({ error: 'Queue not found.' });
    }

    await run('DELETE FROM tickets WHERE queue_id = ?', [queueId]);
    publishQueueUpdate();
    res.json({ message: 'All tickets in this queue were cleared.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tickets/track/:code', async (req, res) => {
  const code = String(req.params.code || '').trim();

  if (!code) {
    return res.status(400).json({ error: 'Ticket code is required.' });
  }

  try {
    const tickets = await query(
      `SELECT t.*, q.name AS queue_name, q.prefix
       FROM tickets t
       JOIN queues q ON q.id = t.queue_id
       WHERE t.code = ?`,
      [code.toUpperCase()]
    );

    if (tickets.length === 0) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    res.json(tickets[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tickets/:id', async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'A valid ticket id is required.' });
  }

  try {
    const result = await query(
      `SELECT t.*, q.name AS queue_name, q.prefix
       FROM tickets t
       JOIN queues q ON q.id = t.queue_id
       WHERE t.id = ?`,
      [id]
    );

    if (result.length === 0) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    res.json(result[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/tickets/:id/status', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const nextStatus = String(req.body?.status || '').trim().toLowerCase();
  const counterNo = req.body?.counter_no != null ? Number(req.body.counter_no) : null;

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'A valid ticket id is required.' });
  }

  const validStatuses = ['waiting', 'called', 'serving', 'served', 'skipped'];
  if (!validStatuses.includes(nextStatus)) {
    return res.status(400).json({ error: 'Status must be one of waiting, called, serving, served, or skipped.' });
  }

  try {
    const ticketRow = await query('SELECT * FROM tickets WHERE id = ?', [id]);
    if (ticketRow.length === 0) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    let sql = 'UPDATE tickets SET status = ?, updated_at = datetime("now")';
    const params = [nextStatus];

    if (nextStatus === 'called') {
      sql += ', called_at = COALESCE(called_at, datetime("now"))';
      if (counterNo !== null && Number.isInteger(counterNo)) {
        sql += ', counter_no = ?';
        params.push(counterNo);
      }
    } else if (nextStatus === 'served') {
      sql += ', served_at = datetime("now")';
      if (counterNo !== null && Number.isInteger(counterNo)) {
        sql += ', counter_no = ?';
        params.push(counterNo);
      }
    } else if (nextStatus === 'waiting') {
      sql += ', called_at = NULL, served_at = NULL';
      if (counterNo !== null && Number.isInteger(counterNo)) {
        sql += ', counter_no = ?';
        params.push(counterNo);
      }
    } else {
      if (counterNo !== null && Number.isInteger(counterNo)) {
        sql += ', counter_no = ?';
        params.push(counterNo);
      }
    }

    sql += ' WHERE id = ?';
    params.push(id);

    await run(sql, params);
    publishQueueUpdate();
    const updatedTicket = await query(
      `SELECT t.*, q.name AS queue_name, q.prefix
       FROM tickets t
       JOIN queues q ON q.id = t.queue_id
       WHERE t.id = ?`,
      [id]
    );
    res.json(updatedTicket[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function startServer() {
  await initDatabase();
  return app.listen(PORT, '0.0.0.0', () => {
    console.log(`QEase server is running on http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error('Failed to start QEase:', error);
    process.exitCode = 1;
  });
}

module.exports = { app, startServer };
