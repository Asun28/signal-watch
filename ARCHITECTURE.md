# Signal Watch: architecture (one page)

```
 inbound only (GET, no inventory-derived parameters)
 NCSC alerts page + alert pages · CISA KEV · CIRCL CVE 5 (paged) · SecurityBrief RSS · OPC · Graph SA · Bluesky · Mastodon
 EPSS threshold pages (filtered locally)                    NCSC email → Cloudflare Email Routing
                │                                                      │
 ┌──────────────▼──────────── one Cloudflare Worker ───────────────────▼─────────────────────────┐
 │ cron */15 (UTC) → NZ clock: run once per day at Settings → Schedule (07:30), digest at 07:45  │
 │ Run now (POST /api/run) and email receipt start the same run; a D1 lock prevents overlap      │
 │ run = Workflow in the same Worker, one step per job, each within the Free 10 ms CPU budget:   │
 │ fetch + parse (one source / page) → dedup (hash keys) → match → NCSC pages → EPSS pages       │
 │   → store items → engine.buildState: group (ladder) + level (rules) → route Act → digest      │
 │ two-way sync (every 15 min, after each run and decision): incidents and tickets               │
 │ UI + JSON API behind Cloudflare Access (Entra ID), or open in demo mode; assets served too    │
 └──────────────┬─────────────────────────────┬────────────────────────────┬─────────────────────┘
                ▼                             ▼                            ▼
   D1 (one small SQLite DB)        Sentinel Logs Ingestion API     Ticket webhook · Teams Workflows
   product, source, run, item,     Direct DCR → SignalWatch_CL     · Graph sendMail
   seen, decision, send, ticket    rule → incident per SignalId    (internal tenants only)
   incident, sim (sync)            incidents API, both ways        tickets: state in, notes out
```

**One engine, two places.** `public/engine.js` holds matching, the grouping ladder, the level rules and the payload builders. The browser runs it to render (live data from `/api/live`, or the replay fixtures); the Worker runs it to route and to build the digest. The 35 rule tests and the replay sets exercise exactly the code that runs in production.

**Data model.** `item(id, run, src, dkey, at, title, url, fields)` where `fields` holds extracted values only (CVEs, advisories, product keys, type, CVSS, KEV dates, act-by, fix, version ranges, peer, sample). `seen(dkey, kept)` holds hashes of everything fetched, so unmatched items are counted once and never stored. `run(at, mode, stats)` keeps per-source status and EPSS deltas. Signals are not stored: they are rebuilt from items in order on every read and run, so threshold and scope changes apply retroactively and grouping is deterministic. Signal ids derive from the founding item (`SW-6001`…). `decision`, `send` (route log, one row per Revision) and `ticket` (key `signal:product`) record what people and the pipeline did. For two-way sync, `incident` and `ticket` hold the external state last seen, `decision.via` marks decisions read back from Sentinel, and `sim` is the sandbox external side in dry run. Retention: items, runs and dedup keys 90 days (Settings → Data).

**Matching.** Product keys come from CPE (`vendor:product`) or a local alias dictionary plus inventory-derived aliases (name, vendor + name; generic words excluded). CIRCL records match on CPE when present; add-on products (plugins, themes) do not match the platform they extend. Management model × signal type (Settings → Scope) decides whether a match counts. Kept: inventory matches, NZ peer incidents, NCSC alerts. Everything else is a count.

**Grouping.** 1 exact IDs (CVE, advisory, canonical URL; multi-hit merges signals into the oldest) → 2 MinHash (char 5-shingles, 128 permutations) Jaccard > 0.85 → 3 same vendor + product within 7 days → 4 embedding similarity → 5 small model for grey-zone pairs, flagged. Disjoint CVE or advisory sets block steps 2 to 5, so templated titles never merge different flaws. Steps 4 and 5 run only with the AI flag; step 5 answers are cached by headline-pair hash. A new source family, new CVE, merge or level rise sets **Updated** and re-opens the signal.

**Levels.** SSVC-style readable rules, thresholds in settings: Act A1 (NCSC alert, matched) and A2 (KEV, matched self-managed); Plan P1 EPSS, P2 CVSS, P3 vendor breach on vendor-managed, P4 act-by within 30 days; Watch W1 tier-3-only, W2 NZ peer without match; caps C1 social-only and C2 tier-3-only at Watch; Info I1 other matches, archived after 14 days; Hidden is a count. Each signal shows the winning rule and every check.

**Routing and idempotency.** After each build, Act signals whose `hash(level, CVEs, advisories, source families)` differs from the last successful send are posted in one batch to `{dce}/dataCollectionRules/{dcr}/streams/Custom-SignalWatch_CL`. `SignalId` is stable and `Revision` increments; the analytics rule takes `arg_max(Revision)` per `SignalId` and groups alerts into one incident, re-opening closed ones. Failed sends retry with the same Revision. Unconfigured integrations run as **dry run** (logged, not sent). Tickets claim `(signal, product)` before the POST.

**Two-way sync.** `src/sync.js` runs on the 15-minute tick, as the last step of a run, and after each decision, without `buildState` (links, decisions and revisions come straight from D1). It reads incidents changed since the last pass (title `Signal Watch · SW-…`) and the state of open tickets in batches, then writes what the latest decision implies. A fetched state that differs from the stored one is an external change; when it is newer than the latest decision it becomes a decision. A decision is written once (its key is kept on the link), so neither side echoes the other, and a decision older than the signal's latest Revision is not written. Unconfigured systems use the sandbox, so the demo runs the same code. Ticket states feed the incident: all resolved closes it as a true positive.

**Boundaries.** The inventory never leaves D1 except as matched product names into our own Sentinel and ticket tenants. Feed requests never carry inventory data, and EPSS is fetched on every run regardless of what needs enriching (acceptance A8 compares outbound requests for two different inventories). The optional model sees one or two headlines; the Fix field is parser-only. Stored content is headline, link, date and extracted fields; article bodies are discarded in the parser. Sync requests carry incident names, ticket refs and label-only comments. Secrets are Worker secrets referenced as `env:NAME`; they never reach the browser or D1. The UI vendors React and the Phosphor icons, so the browser loads nothing third-party except Google Fonts.

**Runs on Workers Free.** A run is a list of small jobs in `src/pipeline.js`. The Workflow (`src/flow.js`) runs each job as one `step.do`, so each gets its own 10 ms CPU budget, outputs are persisted, and a failed step retries without refetching completed ones. Without the Workflow binding (tests, Workers Paid) the same jobs run inline. EPSS on this path uses threshold pages (`epss-gt`, inventory-independent); the bulk file needs Paid. `buildState` re-evaluates only signals whose inputs changed in each run: 3 to 4 times cheaper than a full pass, identical results.

**Operations.** Low maintenance: one Worker (with its Workflow), one D1 database, no queues, no runtime dependencies. Cron every 15 minutes in UTC; the handler applies Pacific/Auckland time, so NZST/NZDT changes need no redeploy. Per run: about 30 steps and 40 s wall time. Observability through Workers Logs (`tick` with the sync counts, `flow`, `api`, `sync` lines) and `wrangler workflows instances`. Tests: `npm test` (81, no network).
