-- Write-only secrets entered in Settings (src/vault.js): AES-GCM ciphertext under the SECRETS_KEY Worker secret.
-- No API returns a value. `bind` is the origin a token may be sent to (ticket token, AI key). The additional
-- authenticated data covers name and bind, so a row cannot be renamed or re-pointed in D1 and still decrypt.
CREATE TABLE IF NOT EXISTS vault (
  name TEXT PRIMARY KEY,
  iv TEXT NOT NULL,
  ct TEXT NOT NULL,
  bind TEXT,
  at INTEGER NOT NULL,
  by TEXT
);
