# Migrating VGenius C Engine to a New VPS

> Goal: move the running instance (code + database + Cloudflare workers + Telegram
> bot) to a new VPS with a short maintenance window, and keep every existing link,
> user, subscription and captured token working.

Current source: `server-v0qz`, code at `/root/vgenius`, service name `vgenius`
(`journalctl -u vgenius`).

---

## Read this first — the 5 things that will actually bite you

1. **Never rotate `ENCRYPTION_KEY` or `SENSITIVE_KEY`.** Copy them verbatim from the
   old `.env`. Every captured token/cookie, login key, chat id and bot credential in
   the database is encrypted with them. Change them and that data is permanently
   unrecoverable — there is no downgrade path.

2. **Only ONE process may poll the Telegram bot token.** `telegram-bot/bot.js` uses
   long polling. Running the old and the new server at the same time with the same
   token makes Telegram alternate updates between them and drop messages. The cutover
   must be **stop old → start new**, not "start new → then stop old".

3. **All cron jobs are in-process** (`node-cron` in `server.js`), not OS crontab.
   Nothing to re-register: session keeper, payment expiry, visitor-timeout cleanup and
   auto-cleanup all start with the app.

4. **Cloudflare workers do not move.** They live in your Cloudflare account and are
   deployed via `CF_API_TOKEN`/`CF_ACCOUNT_ID`. They keep running untouched. But they
   bake `VERIFY_ENDPOINT` from `APP_URL`/`API_URL`, so if the *domain* changes, every
   existing link must be regenerated (see Phase 6).

5. **All state is in MySQL.** Users, links, subscriptions, captured tokens, settings,
   OPSEC config, templates, admins — everything. The DB dump is the migration. If the
   dump is incomplete, the site is hollow.

---

## Phase 0 — Before you touch anything

Do this 24–48h ahead so DNS settles.

```bash
# Cloudflare -> DNS -> your domain -> Edit -> set TTL to 60s (Auto was likely 300+)
```

Then on the **old** server, snapshot everything so you can always roll back:

```bash
cd /root/vgenius
git log --oneline -1                      # note the exact commit you're running
git status --porcelain                    # confirm clean (no local edits you'd lose)
cp .env /root/vgenius.env.bak.$(date +%F) # THE FILE THAT MATTERS
```

Pull the `.env` somewhere safe (it holds `SESSION_SECRET`, `JWT_SECRET`,
`ENCRYPTION_KEY`, `SENSITIVE_KEY`, `ADMIN_SETUP_KEY`, both Cloudflare token sets,
`AZURE_CLIENT_ID`, `TELEGRAM_BOT_TOKEN`, NOWPayments keys and DB creds), **plus the two
things that are also not in GitHub**:

```bash
scp server-v0qz:/root/vgenius/.env /root/vgenius.env.bak

# gitignored runtime data - NOT in the repo, only on the old box
tar czf /root/uploads.tgz -C /root/vgenius uploads   # template background images
tar czf /root/backups.tgz -C /root/vgenius backups 2>/dev/null || true
scp server-v0qz:/root/uploads.tgz /root/backups.tgz /root/

# the systemd unit (the provider flagged this: it is not in the repo either)
scp server-v0qz:/etc/systemd/system/vgenius.service /root/vgenius.service.bak
cat /root/vgenius.service.bak   # note WorkingDirectory + the service user
```

`uploads/backgrounds/` holds every template background image you ever uploaded through the
admin panel. It is gitignored, so a fresh `git clone` will have no images at all — links
using an uploaded background would render broken after migration if you skip this.

---

## Phase 1 — Install on the new VPS

Same spec as the old box (light app; 1 vCPU / 1GB is plenty). Ubuntu 22/24 LTS.

```bash
# 1. Node 20.x (the repo is tested on v20.20.2)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs git mysql-client   # mysql-client only, for the transfer
node -v                                       # expect v20.x

# 2. MySQL 8
apt-get install -y mysql-server
mysql_secure_installation                     # set a root password you control

# 3. PM2, to match the old host (or use the systemd unit at the bottom)
npm install -g pm2
```

Create the database and a dedicated user. Use **different** credentials than the old
box (they only sit in the new `.env`), but keep `vgenius` as the DB name:

```bash
mysql -uroot -p <<'SQL'
CREATE DATABASE vgenius CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vgenius'@'localhost' IDENTIFIED BY 'CHANGE_THIS_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON vgenius.* TO 'vgenius'@'localhost';
FLUSH PRIVILEGES;
SQL
```

Notes:
- `utf8mb4` is required — token/cookie columns hold long encrypted blobs.
- **You do not need to restore `schema.sql`.** `server.js` runs `CREATE INDEX IF NOT
  EXISTS` plus the sensitive/migration routines on boot, so schema drift self-heals.
  Restore the data dump and let boot fill anything missing.
- MySQL only needs to listen locally (`bind-address = 127.0.0.1` is correct).

---

## Phase 2 — Move the database

**Option A — full dump (recommended).**

On the **old** server:
```bash
cd /root
pm2 stop vgenius          # or: systemctl stop vgenius - stop writers before dumping
mysqladmin -uroot -p status
mysqldump -uroot -p --single-transaction --routines --triggers --events \
          vgenius > vgenius_full.sql
gzip vgenius_full.sql
ls -lh vgenius_full.sql.gz       # write the size down; you'll verify it
sha256sum vgenius_full.sql.gz    # write the hash down too
```

Stopping the app for these few seconds is what makes the snapshot authoritative. If you
dump with the app still serving traffic, everything written between the dump and the DNS
switch — captures, visits, payments, subscription state — is lost, because it never made
it into the dump and never reached the new box. Option B below is the alternative if you
cannot accept any pause.

If you are on **MariaDB** (not MySQL), add `--column-statistics=0` to the `mysqldump`
line — without it MariaDB dumps column statistics, which is slow and noisy. On **MySQL**
that flag does not exist and makes `mysqldump` abort with `Unknown option`, so it is left
out of the command above. Check with `mysql --version`.

Transfer:
```bash
scp vgenius_full.sql.gz new-vps-host:~/
```

On the **new** server:
```bash
sha256sum vgenius_full.sql.gz    # must match the old one
gunzip vgenius_full.sql.gz
mysql -uvgenius -p vgenius < vgenius_full.sql
mysql -uvgenius -p vgenius -e "
  SELECT 'users' t, COUNT(*) n FROM users
  UNION ALL SELECT 'links', COUNT(*) FROM links
  UNION ALL SELECT 'captured_tokens', COUNT(*) FROM captured_tokens
  UNION ALL SELECT 'settings', COUNT(*) FROM settings
  UNION ALL SELECT 'admins', COUNT(*) FROM admins
  UNION ALL SELECT 'templates', COUNT(*) FROM templates;"
```

**Cross-check those counts against the old server** before going further:
```bash
mysql -uvgenius -p vgenius -e "SELECT COUNT(*) FROM users; SELECT COUNT(*) FROM captured_tokens;"
```
Numbers must be identical. This is the single best thing you can do to catch a partial
dump. For large DBs add `--quick --order-by-primary`.

**Option B — keep writing to the old DB while testing (no-downtime cutover).**

Point the *new* server's `.env` at the old MySQL:
```
DB_HOST=<old-server-ip>
DB_USER=<a user with access>
DB_PASSWORD=<old-password>
```
Test everything against the live DB, then flip to the new local DB only once you have
a consistent dump. To get that dump, the old server must be **stopped** (Telegram
polling, per gotcha #2) — at that moment the DB is quiescent.

---

## Phase 3 — Code and `.env`

```bash
cd /root
git clone https://github.com/nexa34/V-C-Engineee.git vgenius
cd vgenius
git log --oneline -1        # must match the commit you noted in Phase 0
npm ci                       # not `npm install` — reproducible from the lockfile
```

Copy `.env` over and fix only what the new box needs:

```bash
cp /root/vgenius.env.bak .env
chmod 600 .env              # it holds credentials

# restore the gitignored data (Phase 0 tarballs)
tar xzf /root/uploads.tgz -C /root/vgenius
tar xzf /root/backups.tgz -C /root/vgenius 2>/dev/null || true
```

**If the old box runs under systemd** (its `journalctl` prefix `server-v0qz node[1133]:`
says it does): install the real unit instead of writing one from scratch, because it
holds the `User=`, `WorkingDirectory=` and any `EnvironmentFile=` you may have added:

```bash
cp /root/vgenius.service.bak /etc/systemd/system/vgenius.service
# verify its WorkingDirectory points at /root/vgenius and the service user exists
systemctl daemon-reload
systemctl enable vgenius
# do NOT start it yet - Phase 5 controls the Telegram ordering
```
Otherwise use the appendix unit at the bottom.

Edit **these and only these**:

| Key | Set to |
|---|---|
| `DB_HOST` | `localhost` |
| `DB_USER` / `DB_PASSWORD` | the credentials you created in Phase 1 |
| `APP_URL` | `https://<your-app-domain>` |
| `API_URL` | `https://api.<your-app-domain>` |
| `DC_DIAG` | `0` (keep the server log quiet, as it is now) |

**Do not change**: `SESSION_SECRET`, `JWT_SECRET`, `ENCRYPTION_KEY`,
`SENSITIVE_KEY`, `ADMIN_SETUP_KEY`, `AZURE_CLIENT_ID`, `TELEGRAM_BOT_TOKEN`,
`CF_API_TOKEN`, `CF_ACCOUNT_ID`, `TURNSTILE_CF_API_TOKEN`, `TURNSTILE_CF_ACCOUNT_ID`,
`NOWPAYMENTS_API_KEY`, `NOWPAYMENTS_IPN_SECRET`.

If `APP_URL`/`API_URL` are **unchanged** from the old server, nothing else needs
touching and every existing link keeps working.

**Do not start it here.** The service stays stopped until Phase 5, which controls the
Telegram ordering (only one process may poll the bot token). The boot smoke test below
belongs to Phase 5's start, not here. If you used the *different-bottoken* zero-gap trick
from Phase 5, start it now and run the smoke test, then swap the real token and restart.

Boot smoke test — you want exactly these four lines, nothing more:
```bash
journalctl -u vgenius -n 60 --no-pager
# [Telegram Bot] Started
# [VGenius C Engine] Running on port 3000
# [VGenius C Engine] Environment: production
# [DB] Connected to MySQL
```
Any other line means stop and read it. `[SENSITIVE]` lines are harmless idempotent
backfill, but they mean you imported a pre-migration dump.

---

## Phase 4 — Cutover (do this in one sitting)

The provider's sequence is right, and it must be in this exact order because of the
single-poller rule below:

1. **Old server is already stopped** — you stopped it in Phase 2 to take the dump.
   Confirm it stayed down: `systemctl status vgenius` (or `pm2 status`).
2. **Start the new server**:
   ```bash
   systemctl enable --now vgenius      # or: pm2 start server.js --name vgenius && pm2 save
   journalctl -u vgenius -n 40         # the 4 boot lines from Phase 3's smoke test
   ```
3. **Test on the new IP first**, bypassing DNS entirely:
   ```bash
   curl -sI http://<new-vps-ip>:3000/                     # expect 200/302
   # then open https://<new-vps-ip>/vgadmin-p7x2 over a temporary DNS override or curl:
   curl -sI -H "Host: your-app-domain" http://<new-vps-ip>/  # proves the vhost path works
   ```
   Log in to the admin panel on the new IP and run Phase 7 items 5–11 *before* touching DNS.
4. **Only then switch DNS**: Cloudflare → DNS → point the `A` (and `api`) records at the
   new IP.
5. Wait one TTL (60s, per Phase 0), then confirm from outside:
   ```bash
   dig +short your-app-domain
   curl -sI https://your-app-domain/        # expect 200/302, not a connection error
   ```
6. **Leave the old VPS running but stopped** until Phase 7 is fully green, then
   decommission per the section at the end.

Total blind window: however long Phase 2's stop lasted, seconds. Nothing is served and
nothing is polled during it.

---

## Phase 5 — The Telegram ordering (why the sequence above is mandatory)

The bot may only ever be polled by one process. `telegram-bot/bot.js` long-polls with
`TELEGRAM_BOT_TOKEN`, and if two processes hold that token at once, Telegram alternates
updates between them and **drops messages** — captures would silently go uncaptured.

So: new server only comes up *after* the old one is down (Phase 4 step 1→2). Never
"start new, then stop old".

For a *zero* gap instead, pre-stage the new server with a **different** bot token — a
second @BotFather bot pointed at the same admin chat. Test everything on the new IP,
then swap `TELEGRAM_BOT_TOKEN` to the original and restart. During the test window both
boxes serve the same DB (Option B), so only the second bot polls the real token.

---

## Phase 6 — Links and workers (only if your domain changed)

If `APP_URL` / `API_URL` are **unchanged**, this whole phase is a no-op: every existing
link and worker keeps working exactly as before.

If the domain **did** change:

1. **Workers** keep running — they live in Cloudflare, not on the VPS. But each worker
   bundle baked `__API_BASE` / `VERIFY_ENDPOINT` / beacon URLs at deploy time, so they
   still point at the *old* domain.
2. **Regenerate every active link** from the panel (or call the internal
   deploy/redeploy per link). Each regeneration re-bakes the new `API_URL`, re-runs the
   Turnstile allowed-hostname sync for the new worker host, and re-uploads the worker.
3. **NOWPayments IPN** — the callback URL is derived as
   `${API_URL || APP_URL}/api/payments/ipn`. If the domain changed, update the IPN URL in
   the NOWPayments dashboard to the new one. Otherwise payment confirmations stop arriving
   and every paid order stays `pending` forever.
4. **CF workers subdomain** — links are served from
   `<worker>.<CF_WORKERS_SUBDOMAIN>.workers.dev`. If that subdomain was re-registered,
   all link URLs change and customers' bookmarks go stale; announce the new URLs.

---

## Phase 7 — Full verification checklist (do this before declaring success)

Run against the **new** server, in this order:

| # | Check | Command / action | Expect |
|---|---|---|---|
| 1 | Boot | `journalctl -u vgenius -n 40` | the 4 boot lines only |
| 2 | DB intact | `SELECT COUNT(*) FROM users;` | same as old server (Phase 2) |
| 3 | Admin panel | open `https://<app-domain>/vgadmin-p7x2` with your admin IP | login works |
| 4 | **Admin IP allow-list** | check `ADMIN_IP_WHITELIST` in `.env` + the OPSEC settings row `admin_ip_whitelist_enabled` | your IP is allowed, or the toggle is off — otherwise the panel 403s |
| 5 | User login | sign in with an existing user's credentials | session works (proves `SESSION_SECRET`/`JWT_SECRET` carried over) |
| 6 | Token still decrypts | open the tokens page, view one old captured token | readable JSON, not garbage — proves `ENCRYPTION_KEY` carried over |
| 7 | Sensitive data | check a `login_key` row still unlocks (e.g. telegram still identifies the user) | proves `SENSITIVE_KEY` carried over |
| 8 | Generate link | create a new link, open it | page loads, decrypts, no white-page stall |
| 9 | **Uploaded images** | pick a template that uses an uploaded background, generate a link, view it | background image renders, not a broken image — proves `uploads/` transferred |
| 10 | Device code | click Generate on the new link | user code appears |
| 11 | Sign in with the code | complete the device flow on a test tenant | visitor → `done`, token lands in panel, **Telegram message arrives** |
| 12 | Old link (if domains unchanged) | open a pre-migration link | still works, token still captured |
| 13 | Payment IPN | (only if domain changed) update the NOWPayments dashboard URL, then trigger a test payment | order flips `pending → paid` |
| 14 | Subscriptions | check an active sub's renewal cron ran | `[CRON] session keeper` line in logs |

If every box is ticked, the migration is done.

---

## Rollback (anything goes wrong)

The old server stays **stopped, not deleted**, for at least 48h. Rollback = reverse the
two reversible steps:

1. Cloudflare DNS: point the `A` / `api` records back at the **old** VPS IP.
2. Old server: `cd /root/vgenius && git checkout <commit-from-Phase-0> && pm2 start vgenius`.

Traffic written to the new MySQL between its start and the DNS switch is minimal (DNS
still pointed at the old box, which was stopped). Anything written **after** the DNS
switch is lost on rollback, so roll back promptly. If the new DB already took real
writes you want to keep, dump it, switch DNS back, and import the delta into the old DB.

The safest variant is Phase 2 Option B (new server points at the *live old* DB during
testing): both boxes share one DB, so rollback is just the DNS flip and you lose
nothing — at the cost of the Option-B quirk that the old app must be stopped when you
take the final dump for the cutover.

---

## Decommissioning the old server (after 48h clean)

```bash
cd /root/vgenius
git log --oneline -1            # note final commit
cp .env /root/final-env-backup  # one last copy, keep OFF this box after
pm2 stop vgenius && pm2 delete vgenius
mysqldump -uroot -p vgenius > /root/final-db-dump.sql   # keep both copies
```

Then: revoke/rotate anything scoped to the old box (DB root password, SSH keys, VPS
panel), and keep the two dumps + the `.env` backup encrypted and off the box.

---

## Appendix — systemd unit (alternative to PM2)

Phase 1 mentioned a systemd option. `/etc/systemd/system/vgenius.service`:

```ini
[Unit]
Description=VGenius C Engine
After=network.target mysql.service

[Service]
WorkingDirectory=/root/vgenius
ExecStart=/usr/bin/node /root/vgenius/server.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

`systemctl daemon-reload && systemctl enable --now vgenius`, then
`journalctl -u vgenius` replaces `pm2 logs`. All Phase 7 expectations still apply.
