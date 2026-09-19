from threading import Event
import time

import pytest

from aegis_verify.dashboard.operations_config import OperationsConfig, ConnectionConfig, OperationsError
from aegis_verify.dashboard.operations_inventory import InventoryService
from aegis_verify.connectors.wazuh.inventory import parse_agent, InventoryError


def wait_idle(service):
    deadline = time.monotonic() + 3
    while service.snapshot()['refreshing'] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not service.snapshot()['refreshing']


def test_unconfigured_never_fetches(tmp_path):
    config = OperationsConfig('fixture', ('012',), 'wazuh-alerts-*', tmp_path)
    service = InventoryService(config)
    assert service.snapshot()['state'] == 'not_configured'
    with pytest.raises(OperationsError, match='not_configured'):
        service.refresh()
    service.shutdown()


def test_snapshot_stale_error_and_manual_refresh(tmp_path):
    clock = [0]
    responses = [tuple([parse_agent({'id': '012', 'status': 'active'}, environment_id='fixture',
                    fetched_at='2026-01-01T00:00:00Z')]), InventoryError('permission_denied')]
    calls = []
    def fetch(*a, **kw):
        calls.append(1)
        value = responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value
    config = OperationsConfig('fixture', ('012',), 'wazuh-alerts-*', tmp_path,
        server_api=ConnectionConfig('https://server.invalid', tmp_path / 'ca.pem', 'r', 'p'))
    service = InventoryService(config, fetch_fn=fetch, clock=lambda: clock[0])
    assert service.snapshot()['state'] == 'unavailable' and calls == []
    service.refresh()
    wait_idle(service)
    assert service.snapshot()['state'] == 'ready'
    with pytest.raises(OperationsError, match='rate_limited'):
        service.refresh()
    clock[0] = 61
    assert service.snapshot()['state'] == 'stale'
    service.refresh()
    wait_idle(service)
    snapshot = service.snapshot()
    assert snapshot['state'] == 'stale' and snapshot['error_code'] == 'permission_denied'
    assert snapshot['agents'][0]['source_status'] == 'active'
    assert calls == [1, 1]
    service.shutdown()


def test_parallel_refresh_is_refused(tmp_path):
    release = Event()
    def fetch(*a, **kw):
        release.wait(5)
        raise InventoryError('connection_or_tls_failed')
    config = OperationsConfig('fixture', ('012',), 'wazuh-alerts-*', tmp_path,
        server_api=ConnectionConfig('https://server.invalid', tmp_path / 'ca.pem', 'r', 'p'))
    service = InventoryService(config, fetch_fn=fetch)
    try:
        service.refresh()
        with pytest.raises(OperationsError, match='refresh_busy'):
            service.refresh()
    finally:
        release.set()
        service.shutdown()
    assert service.snapshot()['state'] == 'unavailable'


def test_slow_success_ages_from_capture_start(tmp_path):
    clock = [0]
    def fetch(*args):
        clock[0] = 59
        return (parse_agent({'id': '012'}, environment_id='fixture',
                fetched_at='2026-01-01T00:00:00Z'),)
    config = OperationsConfig('fixture', ('012',), 'wazuh-alerts-*', tmp_path,
        server_api=ConnectionConfig('https://server.invalid', tmp_path / 'ca.pem', 'r', 'p'))
    service = InventoryService(config, fetch_fn=fetch, clock=lambda: clock[0])
    try:
        service.refresh()
        wait_idle(service)
        assert service.snapshot()['state'] == 'ready'
        clock[0] = 61
        assert service.snapshot()['state'] == 'stale'
    finally:
        service.shutdown()
