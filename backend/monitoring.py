"""In-process scheduler for recurring cloud scans."""

import copy
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional


MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 1440


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat(timespec="seconds") if value else None


class ScanMonitor:
    """Runs scans on a daemon thread and keeps credentials only in process memory."""

    def __init__(self, scan: Callable[[str, Dict[str, Any]], Dict[str, Any]]):
        self._scan = scan
        self._lock = threading.RLock()
        self._stop_event: Optional[threading.Event] = None
        self._thread: Optional[threading.Thread] = None
        self._latest_result: Optional[Dict[str, Any]] = None
        self._state = {
            "active": False,
            "running": False,
            "provider": None,
            "interval_minutes": None,
            "started_at": None,
            "last_started_at": None,
            "last_completed_at": None,
            "last_success_at": None,
            "next_run_at": None,
            "last_error": None,
            "total_scanned": None,
            "change_count": 0,
            "changes": [],
        }

    def status(self):
        with self._lock:
            return copy.deepcopy(self._state)

    def latest_result(self):
        with self._lock:
            return copy.deepcopy(self._latest_result)

    def start(self, provider: str, interval_minutes: int, config: Dict[str, Any]):
        if provider not in {"aws", "gcp"}:
            raise ValueError("Provider must be 'aws' or 'gcp'.")
        if not MIN_INTERVAL_MINUTES <= interval_minutes <= MAX_INTERVAL_MINUTES:
            raise ValueError(
                f"Monitoring interval must be between {MIN_INTERVAL_MINUTES} minutes and {MAX_INTERVAL_MINUTES} minutes."
            )
        if provider == "aws" and (not config.get("access_key") or not config.get("secret_key")):
            raise ValueError("AWS IAM access key ID and secret access key are required to monitor AWS.")
        if provider == "gcp" and not config.get("project_id"):
            raise ValueError("Google Cloud Project ID is required to monitor GCP.")

        with self._lock:
            if self._state["active"] or self._state["running"]:
                raise RuntimeError("A monitoring scan is already active. Stop it before starting another.")

            stop_event = threading.Event()
            self._stop_event = stop_event
            self._latest_result = None
            now = _now()
            self._state = {
                "active": True,
                "running": False,
                "provider": provider,
                "interval_minutes": interval_minutes,
                "started_at": _iso(now),
                "last_started_at": None,
                "last_completed_at": None,
                "last_success_at": None,
                "next_run_at": _iso(now),
                "last_error": None,
                "total_scanned": None,
                "change_count": 0,
                "changes": [],
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(provider, interval_minutes, copy.deepcopy(config), stop_event),
                name="cloud-security-monitor",
                daemon=True,
            )
            self._thread.start()
            return copy.deepcopy(self._state)

    def stop(self):
        with self._lock:
            if self._stop_event:
                self._stop_event.set()
            self._state["active"] = False
            self._state["next_run_at"] = None
            return copy.deepcopy(self._state)

    def _run(self, provider: str, interval_minutes: int, config: Dict[str, Any], stop_event: threading.Event):
        interval = timedelta(minutes=interval_minutes)
        while not stop_event.is_set():
            started = _now()
            with self._lock:
                if stop_event.is_set():
                    break
                self._state["running"] = True
                self._state["last_started_at"] = _iso(started)
                self._state["next_run_at"] = None

            try:
                result = self._scan(provider, config)
                analysis = result.get("analysis", [])
                changes = [
                    {
                        "bucket_name": item.get("bucket_name", "unknown"),
                        "provider": item.get("provider", provider),
                        "change": item.get("drift", {}).get("change", "changed"),
                    }
                    for item in analysis
                    if item.get("drift", {}).get("changed")
                ]
                completed = _now()
                with self._lock:
                    self._latest_result = result
                    self._state["last_success_at"] = _iso(completed)
                    self._state["total_scanned"] = result.get("total_scanned", 0)
                    self._state["change_count"] = len(changes)
                    self._state["changes"] = changes[:20]
                    self._state["last_error"] = None
            except Exception as exc:
                completed = _now()
                print(f"[monitor] {provider.upper()} scheduled scan failed: {exc}")
                with self._lock:
                    self._state["last_error"] = f"Scan failed ({type(exc).__name__}). Check the scanner console for details."

            with self._lock:
                self._state["running"] = False
                self._state["last_completed_at"] = _iso(completed)
                if self._state["active"] and not stop_event.is_set():
                    self._state["next_run_at"] = _iso(completed + interval)
                else:
                    self._state["active"] = False
                    self._state["next_run_at"] = None

            if stop_event.wait(interval.total_seconds()):
                break

        with self._lock:
            self._state["active"] = False
            self._state["running"] = False
            self._state["next_run_at"] = None
        config.clear()
