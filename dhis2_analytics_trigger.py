#!/usr/bin/env python3
"""
DHIS2 Analytics Trigger

A small utility to trigger DHIS2 analytics via POST requests, with simple
retry logic, logging, and optional alerting.

Usage examples:
  python dhis2_analytics_trigger.py --mode incremental --config /etc/dhis2_trigger.json
  python dhis2_analytics_trigger.py --mode full --config /etc/dhis2_trigger.json

Sample /etc/dhis2_trigger.json:
{
  "dhis": {
    "base_url": "https://mm.dhis2.net/hmis",  # Root incl. scheme and context path
    "token": "<PASTE_YOUR_TOKEN>",
    "verify_ssl": true,
    "timeout_seconds": 60
  },
  "alerting": {
    "webhook_url": null,
    "only_on_failure": true
  }
}

Notes:
- For base_url like local dev, use e.g. "http://localhost:8080/dhis".
- The script sends the Authorization header as: "Authorization: ApiToken <token>".
- If you instead need Basic auth, leave dhis.token null and set env vars DHIS2_USERNAME/DHIS2_PASSWORD.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from telegram_alerts import send_telegram_alert, format_failure_summary, format_success_summary



@dataclass
class DHISConfig:
    base_url: str
    token: Optional[str] = None
    verify_ssl: bool = True
    timeout_seconds: int = 60

    @property
    def analytics_endpoint(self) -> str:
        base = self.base_url.rstrip("/")
        return f"{base}/api/resourceTables/analytics"


@dataclass
class AlertingConfig:
    telegram: Optional[Dict[str, str]] = None
    webhook_url: Optional[str] = None
    only_on_failure: bool = True


@dataclass
class AppConfig:
    dhis: DHISConfig
    alerting: AlertingConfig


INCREMENTAL_PARAMS = {
    "skipResourceTables": "true",
    "skipOrgUnitOwnership": "true",
    "skipTrackedEntities": "true",
    "skipOutliers": "true",
    "lastYears": "1",
}

FULL_PARAMS = {
    "skipResourceTables": "false",
    "skipOrgUnitOwnership": "false",
    "skipTrackedEntities": "false",
    "skipOutliers": "true"
}


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    dhis_raw = raw.get("dhis", {})
    alert_raw = raw.get("alerting", {})

    dhis_cfg = DHISConfig(
        base_url=dhis_raw.get("base_url", "http://localhost:8080/dhis"),
        token=dhis_raw.get("token") or dhis_raw.get("d2:token"),
        verify_ssl=bool(dhis_raw.get("verify_ssl", True)),
        timeout_seconds=int(dhis_raw.get("timeout_seconds", 60)),
    )

    alert_cfg = AlertingConfig(
        webhook_url=alert_raw.get("webhook_url"),
        telegram=alert_raw.get("telegram"),
        only_on_failure=bool(alert_raw.get("only_on_failure", True)),
    )



    return AppConfig(dhis=dhis_cfg, alerting=alert_cfg)


def make_session(retries: int = 3, backoff_factor: float = 0.5) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("POST", "GET"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def build_headers(cfg: DHISConfig) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if cfg.token:
        headers["Authorization"] = f"ApiToken {cfg.token}"
    else:
        logging.debug("Using Basic Auth via requests.auth if username/password provided.")
    return headers


def post_analytics(
    session: requests.Session,
    cfg: DHISConfig,
    mode: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> requests.Response:
    assert mode in ("incremental", "full"), "mode must be 'incremental' or 'full'"

    params = INCREMENTAL_PARAMS if mode == "incremental" else FULL_PARAMS
    url = cfg.analytics_endpoint
    headers = build_headers(cfg)

    auth = None
    if not cfg.token and username and password:
        auth = requests.auth.HTTPBasicAuth(username, password)

    logging.info("POST %s mode=%s params=%s", url, mode, params)

    resp = session.post(
        url,
        params=params,
        headers=headers,
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_ssl,
        auth=auth,
    )
    return resp


def send_alert(webhook_url: str, payload: Dict[str, Any]) -> None:
    try:
        r = requests.post(webhook_url, json=payload, timeout=15)
        if r.status_code >= 400:
            logging.error("Alert webhook responded with %s: %s", r.status_code, r.text[:500])
    except Exception as e:
        logging.exception("Failed to send alert: %s", e)


def poll_task_logs(
    session: requests.Session,
    cfg: DHISConfig,
    relative_notifier_endpoint: str,
    poll_interval_seconds: int = 10,
    max_wait_seconds: int = 7200,
    grace_seconds_after_complete: int = 10,
) -> Dict[str, Any]:
    """Poll the task log endpoint until completion or timeout.

    Finished = we saw at least one event with completed:true AND
               no new events arrive for a short grace period after that.

    Success  = there exists a completed:true INFO event whose message contains
               'analytics tables updated' (case-insensitive).
    Failure  = otherwise, if the *latest* completed event is ERROR/FATAL
               or looks like a failure.
    """
    base = cfg.base_url.rstrip("/")
    url = f"{base}{relative_notifier_endpoint}"

    headers = build_headers(cfg)

    seen: set[str] = set()
    events: list[dict[str, Any]] = []
    start = time.time()

    completed_seen_at: Optional[float] = None
    last_new_event_at: float = start

    def is_success_event(e: dict) -> bool:
        if not e.get("completed"):
            return False
        lvl = (e.get("level") or "").upper()
        msg = (e.get("message") or "").lower()
        return lvl == "INFO" and "analytics tables updated" in msg

    def is_failure_event(e: dict) -> bool:
        if not e.get("completed"):
            return False
        lvl = (e.get("level") or "").upper()
        msg = (e.get("message") or "").lower()
        return lvl in {"ERROR", "FATAL"} or "fail" in msg or "exception" in msg

    def latest_completed(evts: list[dict]) -> Optional[dict]:
        cand = [e for e in evts if e.get("completed")]
        if not cand:
            return None
        # ISO timestamps sort lexicographically
        return sorted(cand, key=lambda x: x.get("time", ""))[-1]

    while True:
        try:
            r = session.get(url, headers=headers, timeout=cfg.timeout_seconds, verify=cfg.verify_ssl)
            if r.status_code >= 400:
                logging.error("Polling failed %s: %s", r.status_code, r.text[:500])
            else:
                ctype = r.headers.get("Content-Type", "")
                batch = r.json() if "application/json" in ctype else []

                new_count = 0
                for e in batch or []:
                    uid = e.get("uid") or e.get("id")
                    if uid and uid in seen:
                        continue
                    if uid:
                        seen.add(uid)
                    events.append(e)
                    new_count += 1

                if new_count:
                    last_new_event_at = time.time()

                # Stream logs oldest -> newest for readability
                for e in sorted((batch or []), key=lambda x: x.get("time", "")):
                    t = e.get("time") or ""
                    lvl = (e.get("level") or "").upper()
                    msg = e.get("message") or ""
                    logging.info("[TASK] %s %-7s %s", t, lvl, msg)

                # Start grace timer when we first see a completed event
                if any(e.get("completed") for e in batch or []):
                    if completed_seen_at is None:
                        completed_seen_at = time.time()

                # If we've seen completed, wait until no new events for the grace window
                if completed_seen_at is not None:
                    idle_since = max(last_new_event_at, completed_seen_at)
                    if (time.time() - idle_since) >= grace_seconds_after_complete:
                        latest = latest_completed(events)
                        success_marker = any(is_success_event(e) for e in events)
                        failure_marker = latest is not None and is_failure_event(latest)

                        if success_marker:
                            had_errors = False
                        elif failure_marker:
                            had_errors = True
                        else:
                            # Fallback: any ERROR/FATAL anywhere => fail; else succeed
                            had_errors = any((e.get("level") or "").upper() in {"ERROR", "FATAL"} for e in events)

                        duration = time.time() - start
                        return {
                            "finished": True,
                            "had_errors": had_errors,
                            "events": events,
                            "duration_seconds": round(duration, 2),
                        }
        except Exception as e:
            logging.warning("Polling exception: %s", e)

        if time.time() - start > max_wait_seconds:
            return {
                "finished": False,
                "had_errors": True,  # treat timeout as error-ish
                "events": events,
                "duration_seconds": round(time.time() - start, 2),
            }

        time.sleep(poll_interval_seconds)



def trigger_and_watch(
    session: requests.Session,
    app_cfg: AppConfig,
    mode: str,
    watch: bool = True,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> int:
    resp = post_analytics(session, app_cfg.dhis, mode, username=username, password=password)

    try:
        body = resp.json()
    except Exception:
        body = None

    ok = 200 <= resp.status_code < 300
    if not ok:
        logging.error("Trigger failed %s: %s", resp.status_code, resp.text[:800])
        return 1

    logging.info("Trigger accepted: %s", body.get("message") if isinstance(body, dict) else resp.text[:200])

    relative = None
    if isinstance(body, dict):
        resp_obj = body.get("response") or {}
        relative = resp_obj.get("relativeNotifierEndpoint") or body.get("relativeNotifierEndpoint")

    if watch and relative:
        logging.info("Polling task logs at %s", relative)
        summary = poll_task_logs(session, app_cfg.dhis, relative)
        logging.info("Polling finished=%s errors=%s duration=%.1fs", summary["finished"], summary["had_errors"], summary["duration_seconds"])

        result = "SUCCESS" if (summary["finished"] and not summary["had_errors"]) else (
            "TIMEOUT" if not summary["finished"] else "FAILED")
        logging.info("RESULT: %s | finished=%s errors=%s duration=%.1fs events=%d",
                     result, summary["finished"], summary["had_errors"],
                     summary["duration_seconds"], len(summary["events"]))

        if app_cfg.alerting.webhook_url and (summary["had_errors"] or not app_cfg.alerting.only_on_failure):
            payload = {
                "service": "dhis2-analytics-trigger",
                "mode": mode,
                "ok": summary["finished"] and not summary["had_errors"],
                "finished": summary["finished"],
                "had_errors": summary["had_errors"],
                "duration_seconds": summary["duration_seconds"],
                "event_count": len(summary["events"]),
            }
            send_alert(app_cfg.alerting.webhook_url, payload)

        tg = getattr(app_cfg.alerting, "telegram", None)
        if tg:
            # Honor only_on_failure for Telegram as well
            should_send_tg = summary["had_errors"] or (not summary["finished"]) or (
                not app_cfg.alerting.only_on_failure)
            if should_send_tg:
                if summary["finished"] and not summary["had_errors"]:
                    text = format_success_summary(
                        mode=mode,
                        duration_seconds=summary["duration_seconds"],
                        event_count=len(summary["events"]),
                        endpoint=app_cfg.dhis.analytics_endpoint,
                    )
                else:
                    text = format_failure_summary(
                        mode=mode,
                        finished=summary["finished"],
                        had_errors=summary["had_errors"],
                        duration_seconds=summary["duration_seconds"],
                        event_count=len(summary["events"]),
                        endpoint=app_cfg.dhis.analytics_endpoint,
                    )
                send_telegram_alert(tg.get("bot_token"), tg.get("chat_id"), text)

        return 0 if (summary["finished"] and not summary["had_errors"]) else 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Trigger DHIS2 analytics runs.")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    parser.add_argument(
        "--mode",
        choices=["incremental", "full"],
        required=True,
        help="Which analytics run to trigger",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making requests",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional path to log file (default: stderr only)",
    )
    parser.add_argument(
        "--no-watch",
        action="store_true",
        help="Fire-and-forget (do not poll task logs)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=10,
        help="Seconds between task log polls (default: 10)",
    )
    parser.add_argument(
        "--max-wait",
        type=int,
        default=7200,
        help="Max seconds to wait for completion before giving up (default: 7200)",
    )

    args = parser.parse_args()

    log_handlers = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        log_handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=log_handlers,
    )

    cfg = load_config(args.config)

    if args.dry_run:
        logging.info("[DRY-RUN] Would POST to %s with mode=%s", cfg.dhis.analytics_endpoint, args.mode)
        return 0

    session = make_session()

    username = os.getenv("DHIS2_USERNAME")
    password = os.getenv("DHIS2_PASSWORD")

    t0 = time.time()
    try:
        if args.no_watch:
            resp = post_analytics(session, cfg.dhis, args.mode, username=username, password=password)
            ok = 200 <= resp.status_code < 300
            logging.info("Triggered %s (watch disabled) status=%s", args.mode, resp.status_code)
            return 0 if ok else 1
        else:
            code = trigger_and_watch(session, cfg, args.mode, watch=True, username=username, password=password)
            elapsed = time.time() - t0
            logging.info("Total elapsed: %.1fs", elapsed)
            return code

    except Exception as e:
        logging.exception("Unexpected error: %s", e)
        if cfg.alerting.webhook_url:
            send_alert(
                cfg.alerting.webhook_url,
                {
                    "service": "dhis2-analytics-trigger",
                    "mode": args.mode,
                    "ok": False,
                    "error": str(e),
                    "endpoint": cfg.dhis.analytics_endpoint,
                    "timestamp": int(time.time()),
                },
            )
        return 2


if __name__ == "__main__":
    sys.exit(main())
