"""HTTP shipping for collector events — buffer + batch POST.

Per docs/03-COLLECTOR-SPEC.md:
- Buffer locally and batch-POST every N events or T seconds, whichever first
- On backend unreachable: retry with backoff, spool to a local fallback file
  so no data is lost if the backend restarts mid-run
"""

import json
import logging
import os
import time
from pathlib import Path

import requests

log = logging.getLogger("outpost.shipper")


class Shipper:
    def __init__(
        self,
        backend_url: str,
        run_id: str,
        batch_size: int = 20,
        flush_interval: float = 2.0,
        spool_path: str | None = None,
        max_retries: int = 3,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.run_id = run_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.buffer: list[dict] = []
        self.last_flush = time.time()
        self.spool_path = spool_path or str(Path.cwd() / f"outpost-spool-{run_id}.jsonl")

    def add(self, event: dict) -> None:
        """Queue one normalized event dict; flush when thresholds are hit."""
        event["run_id"] = self.run_id
        self.buffer.append(event)
        if len(self.buffer) >= self.batch_size or time.time() - self.last_flush > self.flush_interval:
            self.flush()

    def flush(self) -> None:
        batch = self.buffer
        self.buffer = []

        if batch:
            for attempt in range(self.max_retries):
                try:
                    resp = requests.post(f"{self.backend_url}/ingest/batch", json=batch, timeout=5)
                    resp.raise_for_status()
                    self._replay_spool()
                    self.last_flush = time.time()
                    return
                except requests.RequestException:
                    if attempt < self.max_retries - 1:
                        time.sleep(0.5 * (2**attempt))
                    else:
                        self._spool(batch)
                        log.warning("Backend unreachable — spooled %d events to %s", len(batch), self.spool_path)
            self.last_flush = time.time()
        else:
            # Empty flush still attempts spool replay — without this, a
            # collector with no new events would never push buffered events
            # back after the backend recovers (the buffer check used to
            # early-return and skip replay entirely).
            self._replay_spool()

    # -- fallback spooling ---------------------------------------------------
    def _spool(self, batch: list[dict]) -> None:
        with open(self.spool_path, "a", encoding="utf-8") as fh:
            for ev in batch:
                fh.write(json.dumps(ev) + "\n")

    def _replay_spool(self) -> None:
        """Push any spooled events to the backend now that it's reachable."""
        if not os.path.exists(self.spool_path):
            return
        try:
            with open(self.spool_path, "r", encoding="utf-8") as fh:
                events = [json.loads(line) for line in fh if line.strip()]
            if events:
                requests.post(f"{self.backend_url}/ingest/batch", json=events, timeout=5).raise_for_status()
            os.remove(self.spool_path)
        except Exception:
            log.warning("Spool replay failed — will retry on next successful flush")
