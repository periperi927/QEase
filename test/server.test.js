const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const testDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'qease-tests-'));
const testDatabase = path.join(testDirectory, 'qease-test.db');
process.env.QEASE_DB_PATH = testDatabase;
process.env.QEASE_ADMIN_USERNAME = 'test-admin';
process.env.QEASE_ADMIN_PASSWORD = 'test-only-password-123';
process.env.QEASE_STAFF_PASSWORD = 'test-only-staff-password-123';
process.env.RENDER_EXTERNAL_URL = 'https://qease-test.onrender.com';

const { app } = require('../server');
const { db, initDatabase, query, run } = require('../config/db');

let server;
let baseUrl;
let cookie;
let queueId;

async function jsonRequest(endpoint, options = {}) {
  const response = await fetch(`${baseUrl}${endpoint}`, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.authenticated && cookie ? { Cookie: cookie } : {}),
      ...options.headers,
    },
  });

  const data = await response.json();
  return { response, data };
}

before(async () => {
  await initDatabase();
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
  }

  await new Promise((resolve, reject) => {
    db.close((error) => error ? reject(error) : resolve());
  });

  for (const suffix of ['', '-wal', '-shm']) {
    fs.rmSync(`${testDatabase}${suffix}`, { force: true });
  }
  fs.rmSync(testDirectory, { recursive: true, force: true });
});

test('QEase authentication, queue issuance, QR tracking, analytics, SSE and rate limiting', async (t) => {
  await t.test('requires authentication for staff operations and accepts configured credentials', async () => {
    const unauthorized = await jsonRequest('/api/analytics/today');
    assert.equal(unauthorized.response.status, 401);

    const login = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'test-admin', password: 'test-only-password-123' }),
    });
    assert.equal(login.status, 200);
    assert.match(login.headers.get('set-cookie'), /HttpOnly/);
    assert.match(login.headers.get('set-cookie'), /SameSite=Strict/);
    cookie = login.headers.get('set-cookie').split(';')[0];

    const session = await jsonRequest('/api/admin/session', {
      headers: { Cookie: cookie },
    });
    assert.equal(session.data.user.username, 'test-admin');
    assert.equal(session.data.user.role, 'admin');

    const staffLogin = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'staff', password: 'test-only-staff-password-123' }),
    });
    assert.equal(staffLogin.status, 200);
    assert.equal((await staffLogin.json()).user.role, 'staff');

    const createdQueue = await jsonRequest('/api/queues', {
      method: 'POST',
      authenticated: true,
      body: JSON.stringify({ name: 'Test Queue', prefix: 'TST' }),
    });
    assert.equal(createdQueue.response.status, 201);
    queueId = createdQueue.data.id;
  });

  await t.test('allocates unique tickets concurrently and returns a scannable tracking QR', async () => {
    const tickets = await Promise.all(Array.from({ length: 12 }, () => jsonRequest('/api/tickets/issue', {
      method: 'POST',
      authenticated: true,
      body: JSON.stringify({ queue_id: queueId }),
    })));

    assert.ok(tickets.every(({ response }) => response.status === 201));
    const codes = tickets.map(({ data }) => data.code).sort((left, right) => {
      return Number(left.split('-')[1]) - Number(right.split('-')[1]);
    });
    assert.deepEqual(codes, Array.from({ length: 12 }, (_, index) => `TST-${index + 1}`));

    const issuedTicket = tickets[0].data;
    const trackingUrl = new URL(issuedTicket.trackingUrl);
    assert.equal(trackingUrl.origin, 'https://qease-test.onrender.com');
    assert.equal(trackingUrl.pathname, '/track.html');
    assert.equal(trackingUrl.searchParams.get('ticket'), issuedTicket.code);
    assert.match(issuedTicket.qrCodeDataUrl, /^data:image\/png;base64,/);
    assert.deepEqual(
      Buffer.from(issuedTicket.qrCodeDataUrl.split(',')[1], 'base64').subarray(0, 8),
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
    );
  });

  await t.test('publishes ticket changes to event subscribers', async () => {
    const controller = new AbortController();
    const response = await fetch(`${baseUrl}/api/events`, { signal: controller.signal });
    assert.match(response.headers.get('content-type'), /^text\/event-stream/);
    const reader = response.body.getReader();
    const initialEvent = await reader.read();
    assert.match(new TextDecoder().decode(initialEvent.value), /event: queue:update/);

    const nextCall = reader.read();
    const call = await jsonRequest(`/api/queues/${queueId}/next`, {
      method: 'POST',
      authenticated: true,
      body: JSON.stringify({ counter_no: 4 }),
    });
    assert.equal(call.data.counter_no, 4);
    const updateEvent = await nextCall;
    assert.match(new TextDecoder().decode(updateEvent.value), /event: queue:update/);
    await reader.cancel();
    controller.abort();
  });

  await t.test('reports kiosk positions and today analytics accurately', async () => {
    await run(
      "UPDATE tickets SET created_at = datetime('now', '-5 minutes') WHERE code = 'TST-1'"
    );

    const board = await jsonRequest('/api/kiosk/board');
    assert.equal(board.data.nowServing[0].code, 'TST-1');
    assert.equal(board.data.nowServing[0].counter_no, 4);
    assert.deepEqual(board.data.nextTickets.map((ticket) => ticket.queue_position), [1, 2, 3]);

    const tracking = await jsonRequest('/api/tickets/track/TST-1');
    assert.equal(tracking.data.status, 'called');

    const analytics = await jsonRequest('/api/analytics/today', {
      authenticated: true,
    });
    assert.equal(analytics.data.totalTicketsToday, 12);
    assert.equal(analytics.data.servedTicketsToday, 0);
    assert.ok(analytics.data.averageWaitMinutes >= 4);
    assert.ok(analytics.data.averageWaitMinutes < 6);

    const peakHours = await jsonRequest('/api/analytics/peak-hours', {
      authenticated: true,
    });
    assert.equal(peakHours.data.peakHours.length, 1);
    assert.equal(peakHours.data.peakHours[0].tickets, 12);

    const served = await jsonRequest('/api/tickets/1/status', {
      method: 'PATCH',
      authenticated: true,
      body: JSON.stringify({ status: 'served', counter_no: 4 }),
    });
    assert.equal(served.data.status, 'served');

    const afterServe = await jsonRequest('/api/analytics/today', {
      authenticated: true,
    });
    assert.equal(afterServe.data.servedTicketsToday, 1);
  });

  await t.test('expires authenticated sessions after the configured session lifetime', async () => {
    const realNow = Date.now;
    Date.now = () => realNow() + 8 * 60 * 60 * 1000 + 1;
    let expired;
    try {
      expired = await jsonRequest('/api/admin/session', {
        headers: { Cookie: cookie },
      });
    } finally {
      Date.now = realNow;
    }

    assert.equal(expired.response.status, 401);
  });

  await t.test('rate-limits repeated failed login attempts by client address', async () => {
    for (let index = 0; index < 5; index += 1) {
      const failed = await jsonRequest('/api/admin/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'wrong-user', password: 'wrong-password' }),
      });
      assert.equal(failed.response.status, 401);
    }

    const limited = await jsonRequest('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'test-admin', password: 'test-only-password-123' }),
    });
    assert.equal(limited.response.status, 429);
    assert.ok(Number(limited.response.headers.get('retry-after')) > 0);
  });
});
