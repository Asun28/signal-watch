-- Signal Watch schema. Stored content: headline, link, date and extracted fields only (item.fields JSON).
-- Signals are derived from items on every build (engine.buildState), so they are not stored as rows.

CREATE TABLE IF NOT EXISTS setting (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

-- Inventory. Never sent to any external API.
CREATE TABLE IF NOT EXISTS product (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT '',
  cpe TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL CHECK (model IN ('self', 'shared', 'vendor', 'hyper')),
  decoy INTEGER NOT NULL DEFAULT 0,
  pos INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

-- Sources are config: id, kind, url, parser, tier, schedule, flags, params (JSON in cfg).
CREATE TABLE IF NOT EXISTS source (
  id TEXT PRIMARY KEY,
  cfg TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  pos INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS run (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  mode TEXT NOT NULL,
  ms INTEGER,
  stats TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS run_at ON run (at);

-- Items: headline, link, date, extracted fields. Ids start at 5001 so live signals read SW-6001+.
CREATE TABLE IF NOT EXISTS item (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  src TEXT NOT NULL,
  dkey TEXT NOT NULL UNIQUE,
  at INTEGER NOT NULL,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  fields TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS item_run ON item (run_id);
INSERT INTO item (id, run_id, src, dkey, at, title, url) VALUES (5000, 0, '_', '_seq', 0, '', '');
DELETE FROM item WHERE id = 5000;

-- Dedup keys for everything fetched (kept or not). Hashes only, no content.
CREATE TABLE IF NOT EXISTS seen (
  dkey TEXT PRIMARY KEY,
  kept INTEGER NOT NULL,
  at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS decision (
  id TEXT PRIMARY KEY,
  sig TEXT NOT NULL,
  at INTEGER NOT NULL,
  by TEXT NOT NULL,
  act TEXT NOT NULL CHECK (act IN ('ack', 'na', 'ticket', 'auto')),
  reason TEXT,
  refs TEXT NOT NULL DEFAULT '[]',
  undone_at INTEGER
);
CREATE INDEX IF NOT EXISTS decision_sig ON decision (sig);

-- Route log (Sentinel rows and webhook routes). One row per signal revision.
CREATE TABLE IF NOT EXISTS send (
  sig TEXT NOT NULL,
  rev INTEGER NOT NULL,
  run_id INTEGER,
  at INTEGER NOT NULL,
  hash TEXT NOT NULL,
  to_sys TEXT NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (sig, rev)
);

-- One ticket per signal per product (idempotency key signalId:productId).
CREATE TABLE IF NOT EXISTS ticket (
  sig TEXT NOT NULL,
  pid TEXT NOT NULL,
  ref TEXT,
  sys TEXT NOT NULL,
  status TEXT NOT NULL,
  at INTEGER NOT NULL,
  PRIMARY KEY (sig, pid)
);

-- Grey-zone answers from the optional small model, keyed by headline-pair hash.
CREATE TABLE IF NOT EXISTS ai_pair (
  k TEXT PRIMARY KEY,
  same INTEGER NOT NULL,
  conf REAL NOT NULL,
  at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS digest (
  day TEXT PRIMARY KEY,
  at INTEGER NOT NULL,
  teams TEXT,
  email TEXT
);

-- Advisory lock so the schedule and Run now never overlap.
CREATE TABLE IF NOT EXISTS lock (
  name TEXT PRIMARY KEY,
  until INTEGER NOT NULL,
  owner TEXT NOT NULL
);
