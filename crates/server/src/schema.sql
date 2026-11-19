-- EMS server schema (SQLite), version 2. All timestamps are Unix time in UTC:
-- columns ending in _ms are milliseconds, the rest are seconds.
--
-- Everything belongs to an organisation. Computers carry org_id directly;
-- activity rows belong to a computer and so to its organisation.

-- One row per client company. The agent key is what an installer made for
-- the organisation carries: it is how a computer says whose it is.
CREATE TABLE IF NOT EXISTS orgs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT    NOT NULL,
  name_key      TEXT    NOT NULL UNIQUE,   -- lower case, decides uniqueness
  agent_key     TEXT    NOT NULL UNIQUE,
  api_key_hash  TEXT,
  settings      TEXT,                      -- JSON, see policy::Settings
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS machines (
  id            INTEGER PRIMARY KEY,
  org_id        INTEGER NOT NULL,
  machine_uuid  TEXT    NOT NULL,          -- the computer's name, upper case
  hostname      TEXT,
  os_user       TEXT,
  label         TEXT,
  os_version    TEXT,
  agent_version TEXT,
  ip            TEXT,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  UNIQUE (org_id, machine_uuid)
);

-- One row per stretch of time on one URL. (machine, user, start) is unique,
-- which makes re-sent batches harmless: the duplicate insert is ignored.
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

-- machine_uuid '*' means every computer of the organisation.
CREATE TABLE IF NOT EXISTS blocked_domains (
  id            INTEGER PRIMARY KEY,
  org_id        INTEGER NOT NULL,
  domain        TEXT    NOT NULL,
  machine_uuid  TEXT    NOT NULL DEFAULT '*',
  note          TEXT,
  created_at    INTEGER NOT NULL,
  UNIQUE (org_id, domain, machine_uuid)
);

CREATE TABLE IF NOT EXISTS blacklist_words (
  id          INTEGER PRIMARY KEY,
  org_id      INTEGER NOT NULL,
  word        TEXT    NOT NULL,
  note        TEXT,
  created_at  INTEGER NOT NULL,
  UNIQUE (org_id, word)
);

-- Audit trail of blacklist-word detections, one row per (machine, user, word, domain).
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

-- Attempts to open a blocked site, rolled up per (machine, user, domain, day).
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
  org_id      INTEGER NOT NULL,
  domain      TEXT    NOT NULL,
  category    TEXT    NOT NULL CHECK (category IN ('suspicious', 'neutral', 'productive')),
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (org_id, domain)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS category_keywords (
  id          INTEGER PRIMARY KEY,
  org_id      INTEGER NOT NULL,
  keyword     TEXT    NOT NULL,
  category    TEXT    NOT NULL CHECK (category IN ('suspicious', 'neutral', 'productive')),
  created_at  INTEGER NOT NULL,
  UNIQUE (org_id, keyword, category)
);

-- Every hostname ever reported. Lets a block on example.com also cover the
-- concrete subdomains that have actually been seen, in layers that cannot wildcard.
CREATE TABLE IF NOT EXISTS known_hosts (
  host TEXT PRIMARY KEY
) WITHOUT ROWID;

-- One row per computer: its latest system summary and installed-programs
-- list, both JSON. Replaced whole whenever the agent sends a newer snapshot.
CREATE TABLE IF NOT EXISTS inventory (
  machine_id  INTEGER PRIMARY KEY,
  system      TEXT    NOT NULL,
  apps        TEXT    NOT NULL,
  app_count   INTEGER NOT NULL DEFAULT 0,
  logs        TEXT,                      -- recent agent log lines, JSON array
  updated_at  INTEGER NOT NULL
) WITHOUT ROWID;

-- Restart/shutdown instructions for a computer. One is handed to the computer
-- at its next check-in (sent_at is set then) and never handed over again.
CREATE TABLE IF NOT EXISTS commands (
  id          INTEGER PRIMARY KEY,
  machine_id  INTEGER NOT NULL,
  kind        TEXT    NOT NULL,          -- 'restart' | 'shutdown'
  delay_s     INTEGER NOT NULL DEFAULT 60,
  message     TEXT,
  created_by  TEXT,
  created_at  INTEGER NOT NULL,
  sent_at     INTEGER                    -- NULL until handed to the computer
);
CREATE INDEX IF NOT EXISTS commands_pending ON commands (machine_id) WHERE sent_at IS NULL;

CREATE TABLE IF NOT EXISTS admins (
  id             INTEGER PRIMARY KEY,
  username       TEXT    NOT NULL UNIQUE,
  password_hash  TEXT    NOT NULL,
  role           TEXT    NOT NULL DEFAULT 'owner',   -- 'owner' sees everything; 'member' is limited
  created_at     INTEGER NOT NULL
);

-- Which organisations a member user may reach, and the extra permissions
-- there beyond plain viewing. perms is a comma-separated list drawn from
-- blocking, settings, control, installer.
CREATE TABLE IF NOT EXISTS user_orgs (
  admin_id  INTEGER NOT NULL,
  org_id    INTEGER NOT NULL,
  perms     TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (admin_id, org_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  admin_id    INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
) WITHOUT ROWID;
