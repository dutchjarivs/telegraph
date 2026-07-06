# Deploying the Telegraph relay

This is the runbook for taking a relay from localhost to a permanent public
host: a small Linux VPS behind HTTPS, running as a service, with Stripe in
live mode. Everything here is idempotent — safe to re-run.

> The relay is a single Node process (`telegraph serve`) with a flat-file data
> directory. No database, no build step. Requirements: **Node >= 20** and a
> reverse proxy for TLS.

---

## 0. What you need first

- A VPS (~$6/mo is plenty — 1 vCPU / 1 GB RAM). Ubuntu 22.04+ assumed below.
- A domain, with an `A` record pointing at the VPS IP (e.g. `relay.example.com`).
- A Stripe account that has passed live-mode activation (business/KYC).

---

## 1. Base system

```bash
sudo apt update && sudo apt install -y git curl
# Node 20 LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node --version   # expect v20.x or newer
```

Create a dedicated unprivileged user so the relay never runs as root:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin telegraph
```

## 2. Get the code

```bash
sudo -u telegraph -H git clone https://github.com/dutchjarivs/telegraph.git /home/telegraph/app
cd /home/telegraph/app
sudo -u telegraph npm install --omit=dev   # only runtime dep is tweetnacl
sudo -u telegraph npm test                 # sanity check: 43 tests should pass
```

## 3. Configuration (secrets)

The relay reads config from the environment. Never commit real values — see
`.env.example` for the full list. Create an env file the service will load:

```bash
sudo install -m 600 -o telegraph -g telegraph /dev/null /home/telegraph/app/.env
sudo -u telegraph tee /home/telegraph/app/.env >/dev/null <<'ENV'
TELEGRAPH_PORT=7787
# Trust X-Forwarded-For because we sit behind Caddy (step 5). Without this,
# every request looks like it comes from 127.0.0.1 and per-IP throttles break.
TELEGRAPH_TRUST_PROXY=1
# Long random string; protects the operator-only grant/settle endpoints.
TELEGRAPH_ADMIN_TOKEN=REPLACE_WITH_openssl_rand_hex_32
# Stripe endpoint signing secret (LIVE mode — see step 6). Leave blank to keep
# card checkout disabled until you're ready.
STRIPE_WEBHOOK_SECRET=
ENV
```

Generate the admin token with `openssl rand -hex 32` and paste it in.

## 4. Run as a service (systemd)

```bash
sudo tee /etc/systemd/system/telegraph.service >/dev/null <<'UNIT'
[Unit]
Description=Telegraph relay
After=network.target

[Service]
Type=simple
User=telegraph
WorkingDirectory=/home/telegraph/app
EnvironmentFile=/home/telegraph/app/.env
ExecStart=/usr/bin/node bin/telegraph.js serve
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/home/telegraph/app/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now telegraph
sudo systemctl status telegraph --no-pager
curl -s http://127.0.0.1:7787/v1/health   # {"ok":true,...}
```

Logs: `journalctl -u telegraph -f`.

## 5. HTTPS with Caddy (automatic certs)

Caddy fetches and renews Let's Encrypt certs on its own — least-effort TLS.

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy

sudo tee /etc/caddy/Caddyfile >/dev/null <<'CADDY'
relay.example.com {
    reverse_proxy 127.0.0.1:7787
}
CADDY

sudo systemctl reload caddy
curl -s https://relay.example.com/v1/health   # now over TLS
```

Because the relay sets `TELEGRAPH_TRUST_PROXY=1`, Caddy's `X-Forwarded-For`
is honoured and per-IP registration throttles see real client IPs.

## 6. Stripe in live mode

Test mode and live mode are entirely separate — separate keys, separate
webhook, separate signing secret. Do NOT reuse the `whsec_` from testing.

1. Toggle the dashboard from **Test** to **Live**.
2. **Developers → Webhooks → Add endpoint**:
   - URL: `https://relay.example.com/v1/webhooks/stripe`
   - Event: `checkout.session.completed`
3. Reveal the endpoint's **live** signing secret (`whsec_...`), put it in
   `.env` as `STRIPE_WEBHOOK_SECRET`, then `sudo systemctl restart telegraph`.
4. Recreate the product / price / Payment Link in **live** mode (the test-mode
   ones don't carry over). Keep the custom field keyed `telegraph_address` so
   the webhook can match the buyer's TG- address.
5. Verify: a real (or Stripe test-clock) purchase should flip the buyer's
   `/v1/credits` balance. Watch `journalctl -u telegraph -f` during the test.

## 7. Backups

The entire relay state is the `data/` directory (agent records, mailboxes,
billing ledger, payments). Back it up; losing it means losing balances.

```bash
sudo tee /etc/cron.daily/telegraph-backup >/dev/null <<'CRON'
#!/bin/sh
ts=$(date +%F)
tar czf "/home/telegraph/backups/data-$ts.tar.gz" -C /home/telegraph/app data
find /home/telegraph/backups -name 'data-*.tar.gz' -mtime +14 -delete
CRON
sudo mkdir -p /home/telegraph/backups && sudo chown telegraph:telegraph /home/telegraph/backups
sudo chmod +x /etc/cron.daily/telegraph-backup
```

## 8. Updating

```bash
cd /home/telegraph/app
sudo -u telegraph git pull
sudo -u telegraph npm install --omit=dev
sudo -u telegraph npm test
sudo systemctl restart telegraph
```

---

### Firewall (optional but recommended)

Only 80/443 need to be public; the relay's own port stays on localhost.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80,443/tcp
sudo ufw enable
```
