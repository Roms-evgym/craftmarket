
const { Pool, types } = require("pg");

types.setTypeParser(20, (value) => Number(value));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSLMODE === "disable"
      ? false
      : { rejectUnauthorized: true }
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique
    ON users (LOWER(username))
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS jobs (
      id BIGSERIAL PRIMARY KEY,
      owner_id BIGINT NOT NULL REFERENCES users(id),
      worker_id BIGINT REFERENCES users(id),
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'EUR',
      budget NUMERIC(12, 2) NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      buyer_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
      seller_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS offers (
      id BIGSERIAL PRIMARY KEY,
      job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id),
      amount NUMERIC(12, 2) NOT NULL,
      message TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id),
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function ensureAdmin(password) {
  if (!password || password.length < 12) {
    throw new Error(
      "ADMIN_PASSWORD muss mindestens 12 Zeichen lang sein."
    );
  }

  const existing = await pool.query(
    "SELECT id FROM users WHERE LOWER(username) = LOWER($1)",
    ["Admin"]
  );

 const bcrypt = require("bcryptjs");
const passwordHash = await bcrypt.hash(password, 12);

if (existing.rowCount > 0) {
  await pool.query(
    `UPDATE users
     SET password_hash = $1,
         role = 'admin',
         must_change_password = TRUE
     WHERE LOWER(username) = LOWER($2)`,
    [passwordHash, "Admin"]
  );
  console.log("Admin-Passwort wurde aktualisiert.");
  return;
}

  const bcrypt = require("bcryptjs");
  const passwordHash = await bcrypt.hash(password, 12);

  await pool.query(
    `INSERT INTO users
      (username, password_hash, role, must_change_password)
     VALUES ($1, $2, $3, $4)`,
    ["Admin", passwordHash, "admin", true]
  );
}

async function withTransaction(callback) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  pool,
  initDatabase,
  ensureAdmin,
  withTransaction
};
