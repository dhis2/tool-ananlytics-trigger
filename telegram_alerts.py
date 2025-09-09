#!/usr/bin/env python3
"""
Simple Telegram alert helper for DHIS2 analytics trigger.

Usage (from your main script):

    from telegram_alerts import send_telegram_alert, format_failure_summary

    # Only send on failure
    if summary["had_errors"] or not summary["finished"]:
        text = format_failure_summary(
            mode=mode,
            finished=summary["finished"],
            had_errors=summary["had_errors"],
            duration_seconds=summary["duration_seconds"],
            event_count=len(summary["events"]),
        )
        send_telegram_alert(bot_token, chat_id, text)

Config example (extend your existing JSON):

{
  "dhis": { "base_url": "https://mm.dhis2.net/hmis", "token": "<TOKEN>" },
  "alerting": {
    "webhook_url": null,
    "only_on_failure": true,
    "telegram": {
      "bot_token": "123456:ABCDEF...",
      "chat_id": "-1001234567890"  # can be user id or group/channel id
    }
  }
}
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import requests


TELEGRAM_API_URL = "https://api.telegram.org"


def send_telegram_alert(bot_token: str, chat_id: str, text: str, disable_web_page_preview: bool = True) -> bool:
    """Send a Telegram message via Bot API. Returns True on success, False on error."""
    if not bot_token or not chat_id:
        logging.warning("Telegram not configured (missing bot_token/chat_id)")
        return False

    url = f"{TELEGRAM_API_URL}/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": disable_web_page_preview,
        "parse_mode": "HTML",  # keep formatting simple; avoid Markdown pitfalls
    }

    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code == 429:  # Rate limited; respect retry-after if present
            retry_after = int(r.headers.get("Retry-After", "1"))
            time.sleep(max(1, retry_after))
            r = requests.post(url, json=payload, timeout=15)
        if r.status_code >= 400:
            logging.error("Telegram send failed %s: %s", r.status_code, r.text[:500])
            return False
        data = r.json()
        if not data.get("ok"):
            logging.error("Telegram API error: %s", data)
            return False
        return True
    except Exception as e:
        logging.exception("Telegram send exception: %s", e)
        return False
def format_success_summary(
    *, mode: str, duration_seconds: float, event_count: int, endpoint: Optional[str] = None
) -> str:
    dur = int(round(duration_seconds))
    lines = [
        "<b>DHIS2 analytics SUCCESS</b>",
        f"mode: <code>{mode}</code>",
        f"duration: <code>{dur}s</code>",
        f"events: <code>{event_count}</code>",
    ]
    if endpoint:
        lines.append(f"endpoint: <code>{endpoint}</code>")
    return "\n".join(lines)

def format_failure_summary(
    *,
    mode: str,
    finished: bool,
    had_errors: bool,
    duration_seconds: float,
    event_count: int,
    endpoint: Optional[str] = None,
) -> str:
    """Make a compact, human-friendly failure message for Telegram."""
    status = "FAILED" if had_errors else ("TIMED OUT" if not finished else "UNKNOWN")
    dur = int(round(duration_seconds))
    lines = [
        f"<b>DHIS2 analytics {status}</b>",
        f"mode: <code>{mode}</code>",
        f"duration: <code>{dur}s</code>",
        f"events: <code>{event_count}</code>",
    ]
    if endpoint:
        lines.append(f"endpoint: <code>{endpoint}</code>")
    return "\n".join(lines)

