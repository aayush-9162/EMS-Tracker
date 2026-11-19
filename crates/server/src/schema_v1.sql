-- The layout used before organisations existed (EMS server 1.0).
-- Kept only so the tests can build an old database and upgrade it.

CREATE TABLE IF NOT EXISTS machines (
  id            INTEGER PRIMARY KEY,
  machine_uuid  TEXT    NOT NULL UNIQUE,
  hostname      TEXT,
  os_user       TEXT,
  label         TEXT,
  os_version    TEXT,
  agent_version TEXT,
  ip            TEXT,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS visits (
  id          INTEGER PRIMARY KEY,
  machine_id  INTEGER NOT NULL,
  os_user     TEXT    NOT NULL DEFAULT '',
  domain      TEXT    NOT NULL,
  url         TEXT,
  title       TEXT,
  browser     TEXT,
  start_ms    INTEGER NOT NULL,
  dur_s       INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS visits_key   ON visits (machine_id, os_user, start_ms);
CREATE INDEX        IF NOT EXISTS visits_start ON visits (start_ms);

CREATE TABLE IF NOT EXISTS app_usage (
  id          INTEGER PRIMARY KEY,
  machine_id  INTEGER NOT NULL,
  os_user     TEXT    NOT NULL DEFAULT '',
  app         TEXT    NOT NULL,
  title       TEXT,
  exe         TEXT,
  start_ms    INTEGER NOT NULL,
  dur_s       INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS app_usage_key   ON app_usage (machine_id, os_user, start_ms);
CREATE INDEX        IF NOT EXISTS app_usage_start ON app_usage (start_ms);

CREATE TABLE IF NOT EXISTS blocked_domains (
  id            INTEGER PRIMARY KEY,
  domain        TEXT    NOT NULL,
  machine_uuid  TEXT    NOT NULL DEFAULT '*',
  note          TEXT,
  created_at    INTEGER NOT NULL,
  UNIQUE (domain, machine_uuid)
);

CREATE TABLE IF NOT EXISTS blacklist_words (
  id          INTEGER PRIMARY KEY,
  word        TEXT    NOT NULL UNIQUE,
  note        TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist_hits (
  id            INTEGER PRIMARY KEY,
  machine_id    INTEGER NOT NULL,
  os_user       TEXT    NOT NULL DEFAULT '',
  word          TEXT    NOT NULL,
  domain        TEXT    NOT NULL,
  url           TEXT,
  hit_count     INTEGER NOT NULL DEFAULT 1,
  first_hit_ms  INTEGER NOT NULL,
  last_hit_ms   INTEGER NOT NULL,
  UNIQUE (machine_id, os_user, word, domain)
);
CREATE INDEX IF NOT EXISTS blacklist_hits_last ON blacklist_hits (last_hit_ms);

CREATE TABLE IF NOT EXISTS block_events (
  id          INTEGER PRIMARY KEY,
  machine_id  INTEGER NOT NULL,
  os_user     TEXT    NOT NULL DEFAULT '',
  domain      TEXT    NOT NULL,
  url         TEXT,
  day         INTEGER NOT NULL,
  hit_count   INTEGER NOT NULL DEFAULT 1,
  first_ms    INTEGER NOT NULL,
  last_ms     INTEGER NOT NULL,
  UNIQUE (machine_id, os_user, domain, day)
);
CREATE INDEX IF NOT EXISTS block_events_last ON block_events (last_ms);

CREATE TABLE IF NOT EXISTS domain_categories (
  domain      TEXT PRIMARY KEY,
  category    TEXT    NOT NULL CHECK (category IN ('suspicious', 'neutral', 'productive')),
  updated_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS category_keywords (
  id          INTEGER PRIMARY KEY,
  keyword     TEXT    NOT NULL,
  category    TEXT    NOT NULL CHECK (category IN ('suspicious', 'neutral', 'productive')),
  created_at  INTEGER NOT NULL,
  UNIQUE (keyword, category)
);

CREATE TABLE IF NOT EXISTS known_hosts (
  host TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS admins (
  id             INTEGER PRIMARY KEY,
  username       TEXT    NOT NULL UNIQUE,
  password_hash  TEXT    NOT NULL,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  admin_id    INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) WITHOUT ROWID;
