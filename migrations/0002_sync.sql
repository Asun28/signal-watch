-- Two-way sync with Sentinel incidents and ticket systems (src/sync.js). Each link row holds the last external
-- state seen, so a change on either side is detected by comparison and never echoed back.

-- via NULL: decided in Signal Watch; 'sentinel': read back from the incident. rev: the signal's route revision at
-- the time, so a decision older than a newer revision is not written out.
ALTER TABLE decision ADD COLUMN via TEXT;
ALTER TABLE decision ADD COLUMN rev INTEGER;

-- Ticket links: system id (ServiceNow sys_id, TOPdesk id), state, last external change, last revision noted.
ALTER TABLE ticket ADD COLUMN ext_id TEXT;
ALTER TABLE ticket ADD COLUMN state TEXT NOT NULL DEFAULT 'open';
ALTER TABLE ticket ADD COLUMN ext_at INTEGER;
ALTER TABLE ticket ADD COLUMN rev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ticket ADD COLUMN pushed TEXT;
ALTER TABLE ticket ADD COLUMN synced_at INTEGER;

-- Sentinel incident per routed signal (found by "Signal Watch · SW-…" in the incident title).
CREATE TABLE IF NOT EXISTS incident (
  sig TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  number INTEGER,
  status TEXT NOT NULL,
  cls TEXT,
  owner TEXT,
  ext_at INTEGER,
  pushed TEXT,
  synced_at INTEGER NOT NULL
);

-- Sandbox: the external side in dry run (no Sentinel or ticket system configured), so the demo shows the same
-- sync path. Rows are created by dry-run routes and changed from the signal panel.
CREATE TABLE IF NOT EXISTS sim (
  ref TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('incident', 'ticket')),
  sig TEXT NOT NULL,
  number INTEGER,
  status TEXT NOT NULL,
  cls TEXT,
  owner TEXT,
  rev INTEGER NOT NULL DEFAULT 0,
  notes TEXT NOT NULL DEFAULT '[]',
  at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sim_sig ON sim (sig);
