'use strict';
const { Pool } = require('pg');

// Connects to the online Postgres database and creates the tables the first time.
async function openDb(url) {
  const local = /@(localhost|127\.0\.0\.1)[:/]/.test(url);
  const db = new Pool({
    connectionString: url,
    ssl: local ? false : { rejectUnauthorized: false },
    max: 5
  });

  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      name          TEXT NOT NULL,
      email         TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL CHECK (role IN ('member', 'admin')),
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email));

    CREATE TABLE IF NOT EXISTS books (
      id         SERIAL PRIMARY KEY,
      title      TEXT NOT NULL,
      author     TEXT NOT NULL,
      category   TEXT,
      pdf_file   TEXT,
      image_file TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  return db;
}

module.exports = { openDb };
