# Signal Watch: runbook

Daily security signals for a small NZ public-sector IT team. Collect, keep only what matches the product inventory, group duplicates into one signal per real-world event, set a level by readable rules, route Act signals to Microsoft Sentinel (or a ticket webhook), send a digest.

One Cloudflare Worker (UI, API, 15-minute cron, email ingest, run Workflow) and one D1 database. No runtime dependencies. Runs on Workers Free.

**Live demo:** https://signal-watch.asun28.workers.dev (demo mode: open to anyone, sample inventory, integrations in dry run, Run now once per 10 minutes).

## 1. Run it locally (about 5 minutes)

```sh
npm install
npm run dev              # applies migrations to a local D1, starts http://127.0.0.1:8787
```

Open http://127.0.0.1:8787, press **Run now**. The first run fetches the live sources (about 60 s as Workflow steps) and fills Today. Integrations stay in **dry run** until configured: routes and tickets are recorded, nothing is sent.

Workspaces (Sources page, or Ctrl+K): **Live** (D1) and two replay sets, **Citrix NetScaler** (NCSC update, 14 Oct 2026) and **Manage My Health** (Jan 2026). Replays run in the browser on fixtures and never send anything.

## 2. Tests

```sh
npm test                 # 81 tests, node:test, no network
npm run test:rules       # the 35 rule tests only (same as Settings → Tests and /rules)
```

| Suite | What |
| --- | --- |
| `test/engine.test.js` | Grouping ladder G1–G12, levels L1–L14, matching and privacy M1–M4, routing R1–R5 on both replay sets; seed inventory; CSV import; inventory aliases |
| `test/parsers.test.js` | Every parser against responses recorded on 19 Oct 2026 (`test/fixtures/`) |
| `test/time.test.js` | 07:30 Pacific/Auckland across NZST/NZDT and DST change days |
| `test/acceptance.test.js` | A1–A12 below, driving the real Worker over a `node:sqlite` D1 stand-in |
| `test/steps.test.js` | Workers Free path: a run as Workflow steps (JSON between steps) equals the inline run; Run now → Workflow → status; demo mode locks |
| `test/sync.test.js` | Two-way sync: sandbox in both directions, no echo, last writer wins, stale revisions, ticket chain to the incident; ServiceNow and Sentinel adapters against faked APIs |

The brief's own A1–A12 list was not in the design project. These are mapped from the brief's hard rules and "Done when"; swap in the official wording if it differs.

| Id | Acceptance |
| --- | --- |
| A1 | Run now and the daily 07:30 Pacific/Auckland schedule; DST-safe; once per day; no overlapping runs |
| A2 | Sources are config: a source added through the API is fetched on the next run; disabling skips it |
| A3 | Only inventory matches are stored, the rest is a count; 3 decoys never match; scope by management model; CSV import |
| A4 | One signal per event across sources; a new source updates it, sets Updated and re-opens it; disjoint CVEs stay apart |
| A5 | Levels by rules A1, A2, P2, W2, H1; thresholds come from settings |
| A6 | AI off: complete pipeline, zero model calls; Fix is parser-sourced only |
| A7 | Storage: headline, link, date, extracted fields; no article text in the database |
| A8 | Outbound requests are identical for two different inventories; model input is headlines only |
| A9 | Sentinel Logs Ingestion URL, stream and columns; no resend without change; Revision + 1 on change, same SignalId |
| A10 | One ticket per signal per product; second T creates nothing; templates for ServiceNow, Jira SM, Freshservice, TOPdesk |
| A11 | Digest at 07:45 to Teams Workflows (Adaptive Card) and email (Graph); once per day; labels of at most two words |
| A12 | NCSC page down: the email fallback lands the alert, groups it, routes Act on receipt; the page later joins the same signal |

## 3. Daily routine (30 minutes, business days)

1. **07:30** scheduled run. **07:45** digest in Teams and email.
2. Open **Today**. `J`/`K` move, `Enter` opens the drawer, `Esc` closes.
3. Decide each item: `A` Acknowledge, `N` Not affected (then a reason chip: Version, Not deployed, Config, Mitigated), `T` Ticket (one per signal per product), `U` undo.
4. **Updated** means a new source, new CVE, merge or level rise re-opened it. Check it again.
5. Done when the queue reads **All clear**.

Weekly: Sources page, any **Error** rows? NCSC page outages are covered by the email fallback. Monthly: export Products CSV and confirm owners, versions and management model with the team.

## 4. Deploy to Cloudflare (about 15 minutes)

Works on **Workers Free**. Each run is a Cloudflare Workflow in the same Worker (`src/flow.js`): one step per job (one source or one 100-record CIRCL page, three NCSC alert pages, one 5,000-row EPSS page, store, route, sync), and each step has its own 10 ms CPU budget. A full run is about 30 steps and 40 s. Free allows 3,000 steps a day.

```sh
npx wrangler d1 create signal-watch           # copy database_id into wrangler.jsonc
npm run db:migrate:remote
npx wrangler deploy                           # prints https://signal-watch.<subdomain>.workers.dev
```

Set `APP_URL` in `wrangler.jsonc` to that URL (digest links) and deploy again.

Updating an existing deployment: run `npm run db:migrate:remote` before `npx wrangler deploy` whenever `migrations/` has a new file (`0002_sync.sql` adds the two-way sync tables and columns; it only adds, nothing is dropped).

### Access

| `AUTH_MODE` | Use |
| --- | --- |
| `demo` | Public demo with the **sample inventory only**. Anyone can triage, edit the inventory and thresholds. Integration targets, source URLs and new sources are locked; Run now waits 10 minutes between runs; email ingest is off. The live demo uses this. |
| `access` | Real use. Cloudflare Access in front (Zero Trust → Access → Applications → Self-hosted, identity provider Entra ID, policy: your security group); set `ACCESS_TEAM` and `ACCESS_AUD`. Free for up to 50 users. |
| `basic` | POV fallback: `wrangler secret put BASIC_AUTH` (`user:password`). |
| `none` | Localhost only; any other host gets 503, so the inventory is never public by accident. |

Load a real inventory only after switching from `demo` to `access`.

Secrets (only those you use): `SENTINEL_CLIENT_SECRET`, `TICKET_TOKEN`, `TEAMS_WORKFLOW_URL`, `GRAPH_CLIENT_SECRET`, `AZURE_OPENAI_KEY`. Settings hold `env:NAME` references only; secret values never reach the browser or D1.

### Workers Paid (USD 5/month)

Remove the `workflows` block from `wrangler.jsonc` and runs execute inline in one invocation (30 s CPU). You can then switch the EPSS source to `epss_bulk@1` (the full daily file, about 390,000 rows). Needed once the daily route step outgrows the Free budget (see Known limits).

## 5. Integrations

### Sentinel (Logs Ingestion API, DCR + Entra app)

1. Entra ID → App registrations → new app "Signal Watch". Create a client secret. `npx wrangler secret put SENTINEL_CLIENT_SECRET`.
2. Deploy the table, a Direct DCR (it has its own ingestion endpoint, no DCE needed) and the role assignment:
   ```sh
   az deployment group create -g <rg> -f integrations/sentinel/table-dcr.json \
     -p workspaceName=<workspace> appServicePrincipalObjectId=<enterprise-app-object-id>
   ```
   The outputs are the values for Settings → Sentinel: `dce` (DCE endpoint), `dcr` (immutable id), stream `Custom-SignalWatch_CL`.
3. Analytics rule (one incident per Act signal, grouped by SignalId, re-opens closed incidents):
   ```sh
   az deployment group create -g <rg> -f integrations/sentinel/analytics-rule.json -p workspaceName=<workspace>
   ```
4. Settings → Sentinel: fill Tenant ID, Client ID, DCE, DCR. **Test send** posts one `TEST-` row.

A row is sent only when `hash(level, CVEs, advisories, source families)` changes. `SignalId` is stable, `Revision` increments, failed sends retry on the next run with the same Revision. Columns: `integrations/sentinel/columns.json`; sample row: `sample-record.json`.

### Tickets (fallback route, and the T key)

Settings → Tickets: system, base URL, user (Basic auth systems), `env:TICKET_TOKEN`. Templates and auth notes per system are in `integrations/tickets/`. Settings → Sentinel → **Webhook** routes Act signals to tickets instead of Sentinel. The `ticket` table key `(signal, product)` is claimed before each POST, so retries and repeated `T` never duplicate.

### Two-way sync (Sentinel incidents and tickets)

`src/sync.js` runs every 15 minutes (cron), as the last step of each run, and right after a decision. It compares each linked incident and ticket with the state it last saw there.

| Direction | Sentinel incident | Ticket |
| --- | --- | --- |
| Signal Watch → system | Not affected → Closed · BenignPositive. Acknowledged or Ticketed → Active. Every ticket resolved → Closed · TruePositive. Undo of a close → Active. Each with a comment such as `Signal Watch · Not affected · Version · Aroha T.` | Not affected → resolved, with a close note. New route revision → note `Signal Watch · Updated · r3 · SW-6012` |
| System → Signal Watch | Active → Acknowledged. Closed TruePositive or Undetermined → Acknowledged. Closed BenignPositive or FalsePositive → Not affected. The decision shows the incident owner and "Sentinel" | State (Open, In progress, Resolved, Cancelled) on the signal panel. All resolved closes the incident (above) |

Rules:

- Last writer wins. An external change newer than the latest decision becomes a decision; a newer decision is written out.
- Each decision is written once (the link row keeps its key). Signal Watch never reverts a later change made in the other system, and a retry never duplicates a comment.
- A decision older than the signal's latest Revision is not written: the update re-opened the signal here, and the analytics rule re-opens the incident there.
- Comments and notes are labels and ids. Nothing from the inventory is sent beyond what the ticket already holds.

Setup:

1. Sentinel: give the Entra app **Microsoft Sentinel Responder** on the workspace, then fill Settings → Sentinel → Two-way → Workspace resource ID (the badge changes from Needs workspace to Live):
   ```sh
   az role assignment create --assignee <client-id> --role "Microsoft Sentinel Responder" --scope <workspace-resource-id>
   ```
   Incidents are found by the title the analytics rule sets (`Signal Watch · SW-… · headline`). Requests: `integrations/sentinel/incident-sync.json`.
2. Tickets: the account behind `env:TICKET_TOKEN` needs read, comment and update on tickets (per system: `sync` in `integrations/tickets/*.json`). Settings → Tickets → Close value: ServiceNow close code (default `No resolution provided`), Jira transition id (needed to close; without it only a comment is added), Freshservice status (default 4).
3. Settings → Sentinel or Tickets → **Sync now** runs one pass and shows the counts.

**Sandbox.** With Sentinel or tickets not configured (the demo), dry-run routes create sandbox incidents (`Incident 1001`…) and tickets (`DRY-…`). Each has a Sandbox select on the signal panel: change it as an analyst would, and the same sync code reads it back. The last comment Signal Watch wrote shows next to the select.

### Digest

- Teams: create a Workflow "When a Teams webhook request is received" → post card to a channel. `npx wrangler secret put TEAMS_WORKFLOW_URL` (Settings keeps `env:TEAMS_WORKFLOW_URL`). Sample card: `integrations/teams/digest-card.sample.json`.
- Email: Graph `sendMail` as one mailbox (Settings → Digest: Email from, Email to; Settings → Sentinel: Tenant ID, Client ID). App permission `Mail.Send`, restricted to that mailbox with an application access policy. Secret `GRAPH_CLIENT_SECRET`.

### NCSC email fallback

Cloudflare Email Routing on your domain → route `signalwatch-ingest@<domain>` to this Worker. Subscribe that address to NCSC alerts. Only senders ending in Settings `ncscSenders` (default `ncsc.govt.nz`) are accepted. The alert is grouped and routed on receipt. Without Email Routing, POST the raw message to `/api/ingest/email`.

### AI assist (optional, off by default)

Uncomment `"ai": { "binding": "AI" }` in `wrangler.jsonc` (Workers AI) or set `aiProvider: azure-openai` with `aiEndpoint`, `aiModel` and `AZURE_OPENAI_KEY`. Settings → AI assist adds grouping step 5 (small model on grey-zone pairs, flagged **AI review**) and product extraction for headlines no rule matched. The model receives one or two headlines, never inventory. The Fix field is always parser-sourced. With the flag off the pipeline is complete.

## 6. Sources (config, not code)

Each source is a row: `id, kind, url, parser, tier, schedule, enabled, params`. Seeded from `config/sources.json`; edit on the Sources page or `PUT /api/sources/<id>`. **Add source** takes any RSS/Atom feed (`rss@1`).

| Source | Parser | Tier | Notes |
| --- | --- | --- | --- |
| NCSC NZ alerts | `ncsc_alerts@2` | 1 | Page cards; new alerts' pages give CVEs, CTX ids, CVSS, version ranges (`params.detail`, default 12) |
| NCSC email | `ncsc_email@1` | 1 | On receipt (Email Routing) |
| CISA KEV | `kev_json@1` | 1 | Lookback window (30 d); due date is the act-by |
| FIRST EPSS | `epss_api@1` | 2 | Threshold pages (`epss-gt` = half the Plan threshold, 5,000 rows a page), matched locally; the URL never names a CVE. `epss_bulk@1` reads the full daily file (Workers Paid) |
| CIRCL Vulnerability-Lookup | `circl_recent@1` | 2 | CVE 5 records, 100 per page, pages back 26 h (`params.hours`, `params.pages`) |
| SecurityBrief NZ | `rss@1` | 2 | NZ; breach wording marks an NZ peer incident |
| MS Graph service announcements | `graph_sa@1` | 1 | Optional; app permission `ServiceMessage.Read.All` |
| Privacy Commissioner | `opc_html@1` | 2 | Optional; statements page |
| Bluesky authors | `bsky_author@1` | 3 | Optional; `params.actors` list of handles |
| Mastodon RSS | `rss@1` | 3 | Optional; `https://<instance>/@<user>.rss` |
| ransomware.live, AWS Health | mocks | 3, 1 | **Sample** items only |

Schedules: `Daily` and `With run` (every run), `Weekly Mon` (scheduled runs on that weekday), `On receipt` (push only).

## 7. Levels (Settings → Levels)

| Level | Rules |
| --- | --- |
| Act | A1 NCSC alert on a matched product · A2 KEV on a matched self-managed product |
| Plan | P1 EPSS ≥ 0.1 · P2 CVSS ≥ 9 · P3 vendor breach on a vendor-managed product · P4 act-by ≤ 30 d |
| Watch | W1 tier-3-only match · W2 NZ peer incident, no match · caps C1 social-only, C2 tier-3-only |
| Info | I1 any other match; archived after 14 d |
| Hidden | no in-scope match; count only |

Settings → Scope (management model × signal type) decides which types count for a product. Grouping ladder: 1 exact IDs (CVE, advisory, canonical URL) → 2 MinHash Jaccard > 0.85 → 3 vendor + product within 7 d → 4 embedding → 5 small model (4 and 5 only with AI on). Disjoint CVE or advisory sets block steps 2 to 5.

## 8. Inventory

Products → **Add product** (CPE autocomplete from a local dictionary) or **Import CSV**. Header: `name,vendor,cpe,version,owner,model`; `model` accepts self-managed, shared, vendor-managed, hyperscaler (also on-prem, SaaS, cloud). Sample: `config/inventory-sample.csv` (the 30-product seed, 3 decoys). Changing the inventory clears the noise dedup keys, so items that now match are picked up on the next run. The inventory never leaves D1, except as matched product names in your own Sentinel and ticket systems.

## 9. Troubleshooting

| Symptom | Check |
| --- | --- |
| Source shows Error | Sources → drawer → **Test fetch**; parser drift → fix the parser, bump its version |
| Duplicate signals | Settings → Grouping (Jaccard, vendor window); AI assist for grey-zone pairs |
| Sentinel 403 | Monitoring Metrics Publisher on the DCR for the app's service principal |
| No incident in Sentinel | Rows with `Level == "Act"` in `SignalWatch_CL`; rule enabled; Settings → Sentinel not in Dry run |
| Run did not happen | `npx wrangler tail`; look for `tick` and `flow`; `npx wrangler workflows instances list signal-watch-run`; Settings → Schedule time and days |
| 503 "Auth not configured" | Set `AUTH_MODE` to `access`, `basic` or `demo` |
| 429 "Demo limit" | Demo mode: one Run now per 10 minutes |
| Sync shows errors | `npx wrangler tail`, look for `sync incident` or `sync ticket`. Sentinel 403: Responder role on the workspace. Ticket 401 or 403: token permissions |
| Incident not linked | The incident title starts `Signal Watch · SW-` (analytics rule display name); Settings → Sentinel → Two-way badge shows Live |
| Jira ticket not closed | Settings → Tickets → Close value is the workflow transition id |
| CPU limit exceeded (`exceededCpu`) | `npx wrangler workflows instances describe signal-watch-run <id>` shows the step. Route step: shorten Settings → Data retention, or move to Workers Paid |

## 10. Files

| Path | What |
| --- | --- |
| `public/index.html` | UI: Today, Signals, Products, Sources, Decisions, Settings; drawer; Ctrl+K; J/K/A/N/T/U; light/dark |
| `public/engine.js` | Rules engine shared by browser and Worker: matching, grouping ladder, levels, payloads, fixtures |
| `public/tests.js` | Rule tests (also in the UI) |
| `src/main.js` | Deployed entry: the Worker plus the `RunFlow` Workflow class |
| `src/worker.js` | fetch, scheduled, email handlers |
| `src/pipeline.js` | Run jobs (fetch → dedup → match → enrich → store → rebuild → route) and the driver that runs them inline or as steps |
| `src/flow.js` | Workflow: each job is one `step.do` |
| `src/sync.js` | Two-way sync with Sentinel incidents and tickets; sandbox in dry run |
| `src/sources/` | Parsers (feeds, EPSS, email) |
| `src/routes/` | Sentinel, tickets, digest |
| `src/db.js` | D1 access; `migrations/` schema |
| `integrations/` | Sentinel ARM templates, ticket templates, Teams samples (`npm run templates` regenerates samples) |
| `design/` | The Claude Design source this was built from |
| `ARCHITECTURE.md` | One-page architecture note |

## 11. Known limits

- Workers Free: every step except **route** takes a few milliseconds. Route rebuilds all signals from stored items (about 15 ms warm at 270 items, 35 ms cold) once a day; the platform allows occasional overruns, which covers the demo. With months of items, shorten retention (Settings → Data) or move to Workers Paid.
- EPSS on the Free path is known only at or above the floor (half the Plan threshold); lower scores show as `—`. Rules are unaffected.
- Two-way sync is tested against the documented request and response shapes of each API (faked in `test/sync.test.js`), not yet against a live Sentinel workspace or ticket tenant. After setup, run Sync now once and check the counts and Workers Logs.
- Undo here reopens a Sentinel incident that Signal Watch closed; it does not reopen tickets.
- A reason picked after Not affected (Version, Config…) is stored here but not added to the comment already written.
- The first Sentinel pass reads incidents changed in the last 30 days; later passes read changes since the previous pass, up to 150 a pass.
- KEV entries with a generic product ("Microsoft Windows") do not match a specific product such as Windows Server 2022. Add an alias product or rely on CIRCL CPE matches.
- NCSC alert pages are parsed by pattern; a page redesign needs a parser update (the Sources page shows Error).
- CVSS comes from the feeds themselves (CIRCL, NCSC pages). There are no per-CVE lookups, by design: they would reveal what we run.
- Fonts load from Google Fonts. Self-host Inter if your CSP policy disallows it.
