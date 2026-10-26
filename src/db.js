'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS apis (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  environment TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'monitoring',
  block_threshold TEXT NOT NULL DEFAULT 'medium',
  max_body_kb INTEGER NOT NULL DEFAULT 256,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_apis_customer ON apis(customer_id);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  outcome TEXT NOT NULL,           -- allowed | logged | blocked | rejected | inspection_error
  response_status INTEGER,
  upstream_error INTEGER NOT NULL DEFAULT 0,
  suspicious INTEGER NOT NULL DEFAULT 0,
  highest_severity TEXT,
  body_inspected INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_requests_cust_ts ON requests(customer_id, ts);
CREATE INDEX IF NOT EXISTS idx_requests_api_ts ON requests(api_id, ts);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL,
  api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  explanation TEXT NOT NULL,
  location TEXT NOT NULL,
  action TEXT NOT NULL,            -- logged | blocked
  response_status INTEGER,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_cust_ts ON events(customer_id, ts);
`;

function openDatabase(dbPath) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return db;
}

module.exports = { openDatabase };
