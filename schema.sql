CREATE TABLE IF NOT EXISTS queues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  queue_id INTEGER NOT NULL,
  ticket_no INTEGER NOT NULL,
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'waiting' CHECK(status IN ('waiting', 'called', 'serving', 'served', 'skipped')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  counter_no INTEGER,
  called_at TEXT,
  served_at TEXT,
  FOREIGN KEY(queue_id) REFERENCES queues(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_queue_number
ON tickets(queue_id, ticket_no);

CREATE TABLE IF NOT EXISTS queue_ticket_sequences (
  queue_id INTEGER PRIMARY KEY,
  next_ticket_no INTEGER NOT NULL CHECK(next_ticket_no > 0),
  FOREIGN KEY(queue_id) REFERENCES queues(id) ON DELETE CASCADE
);
