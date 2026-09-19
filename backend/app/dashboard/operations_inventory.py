"""Whole snapshots only; a refresh failure is not an agent disconnection."""
from copy import deepcopy
from dataclasses import asdict
from threading import RLock, Thread
import time

from ..connectors.wazuh.inventory import InventoryConfig, InventoryError, fetch_agents
from .operations_config import OperationsError


class InventoryService:
    def __init__(self, config, *, fetch_fn=fetch_agents, clock=time.monotonic):
        self.config, self._fetch, self._clock = config, fetch_fn, clock
        self._lock, self._worker = RLock(), None
        self._agents, self._fetched_at, self._error = [], None, None
        self._last_start, self._last_success = None, None
        self._closed = False

    def snapshot(self):
        with self._lock:
            state = ('not_configured' if self.config.server_api is None else 'unavailable'
                     if self._last_success is None else 'stale'
                     if self._error or self._clock() - self._last_success > 60 else 'ready')
            return dict(state=state, agents=deepcopy(self._agents), fetched_at=self._fetched_at,
                error_code=self._error, refreshing=self._worker is not None and self._worker.is_alive())

    def refresh(self):
        with self._lock:
            if self._closed:
                raise OperationsError('service_stopped')
            if self.config.server_api is None:
                raise OperationsError('not_configured')
            if self._worker is not None and self._worker.is_alive():
                raise OperationsError('refresh_busy')
            now = self._clock()
            if self._last_start is not None and now - self._last_start < 30:
                raise OperationsError('rate_limited')
            self._last_start = now
            self._worker = Thread(target=self._run, args=(now,), daemon=False)
            self._worker.start()
            return self.snapshot()

    def _run(self, capture_started):
        source = self.config.server_api
        try:
            records = self._fetch(InventoryConfig(source.endpoint, source.ca_file, source.username, source.password),
                                  self.config.environment_id, self.config.agent_ids)
            with self._lock:
                self._agents = [asdict(record) for record in records]
                self._fetched_at = records[0].fetched_at
                self._last_success, self._error = capture_started, None
        except Exception as exc:
            safe_codes = {'authentication_failed', 'permission_denied', 'rate_limited', 'invalid_ca',
                'connection_or_tls_failed', 'incomplete_snapshot', 'refresh_deadline', 'response_too_large',
                'refresh_byte_limit', 'page_limit', 'invalid_response', 'invalid_agent_record', 'invalid_token'}
            with self._lock:
                self._error = str(exc) if isinstance(exc, InventoryError) and str(exc) in safe_codes else 'inventory_failed'

    def shutdown(self):
        with self._lock:
            self._closed, worker = True, self._worker
        if worker is not None:
            worker.join()
