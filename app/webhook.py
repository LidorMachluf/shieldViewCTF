import threading
import time
import json
import logging
from datetime import datetime
from collections import deque

import requests

from app.config import WEBHOOK_URL, WEBHOOK_ENABLED, WEBHOOK_BATCH_SIZE, WEBHOOK_FLUSH_INTERVAL, AUDIT_LOG_PATH

logger = logging.getLogger(__name__)

_event_queue = deque()
_queue_lock = threading.Lock()
_flush_thread = None


def log_event(event: dict):
    event.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")

    # Always write to local audit log
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")

    if not WEBHOOK_ENABLED:
        return

    with _queue_lock:
        _event_queue.append(event)
        if len(_event_queue) >= WEBHOOK_BATCH_SIZE:
            _flush_events()


def _flush_events():
    events = []
    with _queue_lock:
        while _event_queue:
            events.append(_event_queue.popleft())

    if not events:
        return

    try:
        requests.post(
            WEBHOOK_URL,
            json={"events": events},
            timeout=5,
            headers={"Content-Type": "application/json"},
        )
    except Exception as e:
        logger.error(f"Webhook delivery failed: {e}")


def _flush_loop():
    while True:
        time.sleep(WEBHOOK_FLUSH_INTERVAL)
        _flush_events()


def start_flush_thread():
    global _flush_thread
    if WEBHOOK_ENABLED and _flush_thread is None:
        _flush_thread = threading.Thread(target=_flush_loop, daemon=True)
        _flush_thread.start()
