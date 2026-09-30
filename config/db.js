const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const dbPath = process.env.QEASE_DB_PATH
  ? path.resolve(process.env.QEASE_DB_PATH)
  : path.join(__dirname, '..', 'qease.db');
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) {
        reject(err);
        return;
      }

      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function query(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(rows);
    });
  });
}

function initDatabase() {
  const schemaPath = path.join(__dirname, '..', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf8');

  return new Promise((resolve, reject) => {
    db.exec(schema, (err) => {
      if (err) {
        reject(err);
        return;
      }

      db.all('PRAGMA table_info(tickets)', (columnsError, columns) => {
        if (columnsError) {
          reject(columnsError);
          return;
        }

        if (columns.some((column) => column.name === 'called_at')) {
          resolve();
          return;
        }

        db.run('ALTER TABLE tickets ADD COLUMN called_at TEXT', (migrationError) => {
          if (migrationError) {
            reject(migrationError);
            return;
          }

          resolve();
        });
      });
    });
  });
}

module.exports = {
  db,
  run,
  query,
  initDatabase,
};
