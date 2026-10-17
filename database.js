
require("dotenv").config();

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const dataDir = process.env.DATA_DIR || __dirname;
fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, "craftmarket.sqlite");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
      CHECK (role IN ('admin', 'user')),
    must_change_password INTEGER NOT NULL DEFAULT 1,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    worker_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency IN ('EUR', 'COINS')),
    budget_cents INTEGER NOT NULL CHECK (budget_cents > 0),
    agreed_cents INTEGER,
    status TEXT NOT NULL DEFAULT 'open'
      CHECK (status IN ('open', 'in_progress', 'completed', 'cancelled')),
    buyer_confirmed INTEGER NOT NULL DEFAULT 0,
    seller_confirmed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS offers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
  CREATE INDEX IF NOT EXISTS idx_offers_job ON offers(job_id);
  CREATE INDEX IF NOT EXISTS idx_messages_job ON messages(job_id);
`);

function ensureAdmin(initialPassword) {
  if (typeof initialPassword !== "string" ||
      initialPassword.length < 12 ||
      initialPassword.length > 200) {
    throw new Error(
      "ADMIN_PASSWORD muss zwischen 12 und 200 Zeichen lang sein."
    );
  }

  const existing = db.prepare(
    "SELECT id FROM users WHERE username = 'Admin' COLLATE NOCASE"
  ).get();

  if (!existing) {
    db.prepare(`
      INSERT INTO users
        (username, password_hash, role, must_change_password, disabled)
      VALUES ('Admin', ?, 'admin', 0, 0)
    `).run(bcrypt.hashSync(initialPassword, 12));

    console.log("Admin-Konto wurde eingerichtet.");
  }
}

module.exports = { db, ensureAdmin };
