# DHIS2 Analytics Trigger

A Python utility to trigger DHIS2 analytics via `POST` and (optionally)
watch progress, log output, and send alerts (generic webhook + Telegram).

Some installations of DHIS2 have reported issues running analytics with the
built-in scheduler, so this script can be run from cron instead. The added advantage
is that you can get notified of failures via Telegram or any webhook.

## What it does
- Triggers incremental or full analytics runs:
  - Incremental: skips resource tables; `lastYears=1`
  - Full: includes resource tables; `lastYears=5`
- Polls `/api/system/tasks/ANALYTICS_TABLE/<id>` until completion, then classifies the outcome.
- Sends alerts:
  - **Webhook** (any JSON endpoint)
  - **Telegram** (bot token + chat id)
  - Respects `only_on_failure` for both paths.

## Files
- `dhis2_analytics_trigger.py` – main script
- `telegram_alerts.py` – Telegram helper
- `requirements.txt`

## Install (venv recommended)
```bash
sudo mkdir -p /opt/dhis2-analytics-trigger && cd /opt/dhis2-analytics-trigger
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Configure
Create `/etc/dhis2_trigger.json`:
```json
{
  "dhis": {
    "base_url": "https://play.im.dhis2.org/stable-2-42-1",
    "token": "<PASTE_TOKEN>",
    "verify_ssl": true,
    "timeout_seconds": 60
  },
  "alerting": {
    "webhook_url": null,
    "only_on_failure": true,
    "telegram": {
      "bot_token": "123456:ABCDEF...",
      "chat_id": "-1001234567890"
    }
  }
}
```
> For local/dev DHIS2 use e.g. `http://localhost:8080` as `base_url`.


If you want to use the Telegram alerts, create a bot with [BotFather](https://t.me/botfather)
and get your chat ID with [@userinfobot](https://t.me/userinfobot). For group chats, add the 
bot to the group and promote it to admin.
## Run
```bash
# Dry run
python dhis2_analytics_trigger.py --mode incremental --config /etc/dhis2_trigger.json --dry-run

# Incremental
python dhis2_analytics_trigger.py --mode incremental --config /etc/dhis2_trigger.json

# Full
python dhis2_analytics_trigger.py --mode full --config /etc/dhis2_trigger.json
```
CLI flags: `--poll-interval`, `--max-wait`, `--no-watch`.

## Cron

Below is an example `crontab -e` entry to run incremental analytics every 15 min
during business hours (Mon–Fri, 08:00–17:59) and a full run daily at 01:00. Adjust
the paths and parameters as needed.

```cron
TZ=Africa/Nairobi
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Incremental: every 15 min, 08:00–17:59, Mon–Fri
*/15 8-17 * * 1-5 /usr/bin/flock -n /var/lock/dhis2-analytics.lock /opt/dhis2-analytics-trigger/.venv/bin/python /opt/dhis2-analytics-trigger/dhis2_analytics_trigger.py --mode incremental --config /etc/dhis2_trigger.json >> /var/log/dhis2_trigger.log 2>&1

# Full: daily at 01:00 (allow up to 6h)
0 1 * * * /usr/bin/flock -n /var/lock/dhis2-analytics.lock /opt/dhis2-analytics-trigger/.venv/bin/python /opt/dhis2-analytics-trigger/dhis2_analytics_trigger.py --mode full --max-wait 21600 --config /etc/dhis2_trigger.json >> /var/log/dhis2_trigger.log 2>&1
```

## How success/failure is detected
- Success: an `INFO` event with `completed:true` and a message like **"Analytics tables updated: …"**.
- Failure: latest `completed:true` event is `ERROR`/`FATAL`, or any fatal signal with no success marker.
- A short grace window is used after the first `completed:true` to catch trailing events.

## Troubleshooting
- **Auth**: uses `Authorization: ApiToken <token>`. For Basic auth, set `DHIS2_USERNAME` / `DHIS2_PASSWORD` env vars. Note that the use of Basic Authentication is discouraged.
- **SSL**: set `verify_ssl:false` temporarily to diagnose CA issues (fix CA properly for prod).
- **Overlaps**: `flock` prevents incremental/full collisions.
- **Logs**: `/var/log/dhis2_trigger.log`; set up logrotate if needed.

---
Tweak `lastYears` in the params if your DHIS2 needs a different window.
