"""Bounded read-only Indexer collection. No remote execution or security verdicts."""
import argparse
import base64
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone, timedelta
import hashlib
import fnmatch
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

from aegis_verify.models import PreciseTimestamp
from aegis_verify.private_fs import mkdir_private
from ._json import decode_document, MAX_BYTES
from .errors import WazuhParseError
from .parser import parse_wazuh_document
from .windows_telemetry import parse_wazuh_sysmon1_document, parse_wazuh_powershell4104_document


class LiveError(Exception):
    """Only fixed diagnostic codes; never include endpoints, raw data or secrets."""


@dataclass(frozen=True)
class Config:
    endpoint: str = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)
    index: str
    agent_id: str
    start: str
    end: str
    environment_id: str
    collection_mode: str = 'unknown'
    ca_file: str | None = field(default=None, repr=False)
    page_size: int = 20
    max_records: int = 100
    max_pages: int = 100

    def __post_init__(self):
        try:
            url = urlsplit(self.endpoint)
            valid = (url.scheme == 'https' and url.hostname and not url.username and not url.password
                     and url.path in ('', '/') and not url.query and not url.fragment
                     and not any(c.isspace() for c in self.endpoint))
            _ = url.port
            start, end = PreciseTimestamp.parse(self.start), PreciseTimestamp.parse(self.end)
        except (ValueError, TypeError, AttributeError):
            raise LiveError('invalid_config') from None
        if not valid or start >= end:
            raise LiveError('invalid_config')
        if not re.fullmatch(r'[a-z0-9][a-z0-9._*-]{0,127}', self.index) or '..' in self.index:
            raise LiveError('invalid_index')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', self.agent_id):
            raise LiveError('invalid_agent')
        if (not self.username or ':' in self.username or not self.password
                or not self.environment_id.strip() or self.collection_mode not in ('direct', 'forwarded', 'unknown')):
            raise LiveError('invalid_config')
        for value, limit in ((self.page_size, 100), (self.max_records, 100), (self.max_pages, 100)):
            if type(value) is not int or not 1 <= value <= limit:
                raise LiveError('invalid_limit')


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsTransport:
    """TLS required, no ambient proxies or redirects, only this collector's routes."""
    def __init__(self, config):
        self._config = config
        try:
            self.context = ssl.create_default_context(cafile=config.ca_file)
        except (OSError, ssl.SSLError):
            raise LiveError('invalid_ca') from None
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(context=self.context), _NoRedirect())

    def request(self, method, path, body):
        initial = f'/{self._config.index}/_search?scroll=1m'
        health = f'/{self._config.index}/_search'
        if (method, path) not in {('POST', initial), ('POST', health), ('POST', '/_search/scroll'), ('DELETE', '/_search/scroll')}:
            raise LiveError('unsupported_request')
        if path == health and (type(body) is not dict or body.get('size') != 0):
            raise LiveError('unsupported_request')
        auth = base64.b64encode(f'{self._config.username}:{self._config.password}'.encode()).decode()
        request = Request(self._config.endpoint.rstrip('/') + path,
                          data=json.dumps(body, allow_nan=False).encode(), method=method,
                          headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json',
                                   'Accept': 'application/json', 'Accept-Encoding': 'identity'})
        for attempt in range(3):
            try:
                with self._opener.open(request, timeout=10) as response:
                    raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise LiveError('response_too_large')
                return raw
            except HTTPError as error:
                status = error.code
                retry_after = error.headers.get('Retry-After', '')
                error.close()
                if status == 429 and attempt < 2:
                    if retry_after and (not retry_after.isascii() or not retry_after.isdigit() or len(retry_after) > 2 or int(retry_after) > 10):
                        raise LiveError('rate_limited') from None
                    time.sleep(max(2 ** attempt, int(retry_after or '0')))
                    continue
                code = {401: 'authentication_failed', 403: 'permission_denied', 429: 'rate_limited'}.get(status, 'http_error')
                raise LiveError(code) from None
            except (ssl.SSLError, URLError, OSError, ValueError, HTTPException):
                # A lost scroll response is ambiguous: replay could skip a page.
                raise LiveError('connection_or_tls_failed') from None
        raise LiveError('rate_limited')


def _json(raw):
    try:
        return decode_document(raw)
    except WazuhParseError:
        raise LiveError('invalid_response') from None


@dataclass(frozen=True)
class ProbeResult:
    healthy: bool
    code: str

    def __post_init__(self):
        if type(self.healthy) is not bool or self.code != ('healthy' if self.healthy else 'source_unavailable'):
            raise ValueError('invalid_probe_result')


def probe(config: Config, *, transport=None) -> ProbeResult:
    """One bounded authenticated index query; no scroll, files, events or verdict."""
    try:
        if type(config) is not Config:
            return ProbeResult(False, 'source_unavailable')
        transport = transport or HttpsTransport(config)
        body = {'size': 0, 'timeout': '5s', 'track_total_hits': False,
                'query': {'bool': {'filter': [
                    {'term': {'agent.id': config.agent_id}},
                    {'range': {'timestamp': {'gte': config.start, 'lt': config.end}}}]}}}
        doc = _json(transport.request('POST', f'/{config.index}/_search', body))
        shards = doc.get('_shards')
        if (doc.get('timed_out') is not False or doc.get('terminated_early', False) is not False
                or type(shards) is not dict
                or any(type(shards.get(k)) is not int for k in ('failed', 'successful', 'total'))
                or shards['failed'] != 0 or shards['total'] <= 0 or shards['successful'] != shards['total']
                or type(doc.get('hits')) is not dict or doc['hits'].get('hits') != []):
            return ProbeResult(False, 'source_unavailable')
        return ProbeResult(True, 'healthy')
    except (LiveError, ValueError, TypeError, AttributeError, OSError):
        return ProbeResult(False, 'source_unavailable')


def _write(path, raw):
    try:
        with path.open('xb') as stream:
            stream.write(raw)
    except OSError:
        raise LiveError('output_error') from None


def _encode(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


PROFILES = {
    ('Microsoft-Windows-Security-Auditing', 'Security', '4688'): ('wazuh-win4688-v2', parse_wazuh_document),
    ('Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon/Operational', '1'): ('wazuh-sysmon1-v1', parse_wazuh_sysmon1_document),
    ('Microsoft-Windows-PowerShell', 'Microsoft-Windows-PowerShell/Operational', '4104'): ('wazuh-powershell4104-v1', parse_wazuh_powershell4104_document),
}


def _map(hit, config, ref, ingested_at):
    try:
        source = hit['_source']
        if source['agent']['id'] != config.agent_id:
            raise LiveError('scope_mismatch')
        if not fnmatch.fnmatchcase(hit['_index'], config.index):
            raise LiveError('scope_mismatch')
        source_time = source['timestamp']
        if isinstance(source_time, str):
            source_time = re.sub(r'([+-][0-9]{2})([0-9]{2})$', r'\1:\2', source_time)
        stamp = PreciseTimestamp.parse(source_time)
        if not PreciseTimestamp.parse(config.start) <= stamp < PreciseTimestamp.parse(config.end):
            raise LiveError('scope_mismatch')
        system = source['data']['win']['system']
        key = (system['providerName'], system['channel'], system['eventID'])
        if key not in PROFILES:
            raise LiveError('unsupported_profile')
        parser_id, parser = PROFILES[key]
        derived = _encode(hit)
        context = dict(ingested_at=ingested_at, collection_mode=config.collection_mode)
        event = parser(derived, source_ref=ref, environment_id=config.environment_id, **context).event
        return parser_id, derived, context, event
    except (KeyError, TypeError, ValueError, WazuhParseError):
        raise LiveError('unsupported_or_invalid_record') from None


def collect(config, output, *, transport=None):
    """Publish inputs only after all pages validate. Retain failures as INCOMPLETE.

    Raw responses are original bytes; hit files are explicitly JSON derivatives.
    No evaluation profile or collection-completeness attestation is generated.
    """
    transport = transport or HttpsTransport(config)
    output = Path(output)
    try:
        mkdir_private(output)
    except FileExistsError:
        raise LiveError('output_exists') from None
    except OSError:
        raise LiveError('output_error') from None
    _write(output / 'INCOMPLETE', b'Collection has not completed. Do not evaluate this directory.\n')
    cursor, cleanup_failed = None, False
    files, events, responses, derivations, seen = [], [], [], [], set()
    total, byte_count, completed = None, 0, False
    ingested_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    body = {'size': config.page_size, 'sort': ['_doc'], 'track_total_hits': True,
            'query': {'bool': {'filter': [
                {'term': {'agent.id': config.agent_id}},
                {'range': {'timestamp': {'gte': config.start, 'lt': config.end}}},
                {'bool': {'minimum_should_match': 1, 'should': [
                    {'bool': {'filter': [
                        {'term': {'data.win.system.providerName': provider}},
                        {'term': {'data.win.system.channel': channel}},
                        {'term': {'data.win.system.eventID': event_id}},
                    ]}} for provider, channel, event_id in PROFILES
                ]}},
            ]}}}
    path = f'/{config.index}/_search?scroll=1m'
    try:
        for page_no in range(1, config.max_pages + 1):
            if time.monotonic() - started > 300:
                raise LiveError('collection_deadline')
            raw = transport.request('POST', path, body)
            byte_count += len(raw)
            if byte_count > 16 * 1024 * 1024:
                raise LiveError('collection_byte_limit')
            response_name = f'response-{page_no:04d}.json'
            _write(output / response_name, raw)
            responses.append({'path': response_name, 'sha256': _hash(raw)})
            doc = _json(raw)
            new_cursor = doc.get('_scroll_id')
            if type(new_cursor) is str and 0 < len(new_cursor) <= 16384:
                cursor = new_cursor
            else:
                raise LiveError('invalid_cursor')
            shards = doc.get('_shards', {})
            if (doc.get('timed_out') is not False or doc.get('terminated_early', False) is not False
                    or not isinstance(shards, dict)
                    or any(type(shards.get(k)) is not int for k in ('failed', 'successful', 'total'))
                    or shards['failed'] != 0 or shards['total'] <= 0
                    or shards['successful'] != shards['total']):
                raise LiveError('partial_response')
            block = doc.get('hits')
            if type(block) is not dict or type(block.get('hits')) is not list:
                raise LiveError('invalid_hits')
            count = block.get('total')
            if (type(count) is not dict or count.get('relation') != 'eq'
                    or type(count.get('value')) is not int or count['value'] < 0):
                raise LiveError('inexact_total')
            if total is None:
                total = count['value']
            if count['value'] != total:
                raise LiveError('count_limit_or_mismatch')
            if total > config.max_records:
                raise LiveError('record_limit')
            hits = block['hits']
            if len(hits) > config.page_size:
                raise LiveError('page_limit')
            if not hits:
                if len(files) != total:
                    raise LiveError('count_mismatch')
                completed = True
                break
            for position, hit in enumerate(hits):
                if type(hit) is not dict or any(type(hit.get(k)) is not str or not hit[k] for k in ('_id', '_index')):
                    raise LiveError('invalid_identity')
                identity = (hit['_index'], hit['_id'])
                if identity in seen:
                    raise LiveError('duplicate_record')
                seen.add(identity)
                if len(seen) > total or len(seen) > config.max_records:
                    raise LiveError('count_limit_or_mismatch')
                ref = f'hit-{len(files) + 1:06d}'
                parser_id, derived, context, event = _map(hit, config, ref, ingested_at)
                name = ref + '.json'
                _write(output / name, derived)
                files.append(dict(path=name, source_ref=ref, parser=parser_id, sha256=_hash(derived), context=context))
                events.append(event.model_dump(mode='json'))
                derivations.append(dict(path=name, sha256=_hash(derived), response=response_name,
                                        pointer=f'/hits/hits/{position}', transformation='json-serialization'))
            path, body = '/_search/scroll', {'scroll': '1m', 'scroll_id': cursor}
        if not completed:
            raise LiveError('page_limit')
    finally:
        if cursor is not None:
            try:
                cleared = _json(transport.request('DELETE', '/_search/scroll', {'scroll_id': [cursor]}))
                cleanup_failed = cleared.get('succeeded') is not True
            except LiveError:
                cleanup_failed = True
            if cleanup_failed and not completed:
                raise LiveError('cleanup_failed') from None
    summary = dict(schema_version='0.1.0', record_count=len(events), collection_assurance='unknown',
                   query_complete=True, cleanup_failed=cleanup_failed, index=config.index,
                   agent_id=config.agent_id, start=config.start, end=config.end,
                   timestamp_basis='wazuh.timestamp', end_exclusive=True,
                   profiles=[name for name, _ in PROFILES.values()],
                   responses=responses, derivations=derivations)
    _write(output / 'canonical.json', _encode(events))
    _write(output / 'collection.json', _encode(summary))
    # Existing intake requires at least one input; empty collections remain diagnostic only.
    if files:
        _write(output / 'inputs.json', _encode(dict(bundle_schema_version='0.1.0', environment_id=config.environment_id, files=files)))
    try:
        (output / 'INCOMPLETE').unlink()
    except OSError:
        raise LiveError('output_error') from None
    return summary


def collect_adaptive(config, output, *, transport=None, max_attempts=63):
    """Collect disjoint leaves; never merge them into an oversized intake bundle.

    Each leaf is a separate snapshot, not a single atomic batch snapshot.
    Failed parent attempts remain private evidence, excluded from batch.json.
    """
    if type(max_attempts) is not int or not 1 <= max_attempts <= 63:
        raise LiveError('invalid_limit')
    transport = transport or HttpsTransport(config)
    output = Path(output)
    try:
        mkdir_private(output)
    except FileExistsError:
        raise LiveError('output_exists') from None
    except OSError:
        raise LiveError('output_error') from None
    _write(output / 'INCOMPLETE', b'Adaptive batch incomplete. Do not evaluate as a complete batch.\n')
    started = time.monotonic()
    pending = [(config, 0)]
    leaves, attempts = [], 0
    while pending:
        if attempts >= max_attempts:
            raise LiveError('batch_attempt_limit')
        if time.monotonic() - started >= 600:
            raise LiveError('batch_deadline')
        current, depth = pending.pop()
        attempts += 1
        name = f'attempt-{attempts:04d}'
        try:
            summary = collect(current, output / name, transport=transport)
        except LiveError as error:
            if str(error) != 'record_limit':
                raise
            start = PreciseTimestamp.parse(current.start).epoch_nanoseconds
            end = PreciseTimestamp.parse(current.end).epoch_nanoseconds
            if depth >= 12 or end - start < 2_000_000_000:
                raise LiveError('split_limit') from None
            seconds, nanos = divmod((start + end) // 2, 1_000_000_000)
            whole = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
            midpoint = f'{whole.year:04d}-{whole.month:02d}-{whole.day:02d}T{whole.hour:02d}:{whole.minute:02d}:{whole.second:02d}.{nanos:09d}Z'
            pending.append((replace(current, start=midpoint), depth + 1))
            pending.append((replace(current, end=midpoint), depth + 1))
            continue
        try:
            collection_hash = _hash((output / name / 'collection.json').read_bytes())
        except OSError:
            raise LiveError('output_error') from None
        leaves.append(dict(path=name, start=current.start, end=current.end,
                           record_count=summary['record_count'],
                           cleanup_failed=summary['cleanup_failed'],
                           collection_sha256=collection_hash))
    result = dict(schema_version='0.1.0', start=config.start, end=config.end,
                  agent_id=config.agent_id, index=config.index, collections=leaves,
                  attempts=attempts, record_count=sum(x['record_count'] for x in leaves),
                  query_complete=True, collection_assurance='unknown',
                  snapshot_scope='per-collection',
                  cleanup_failed=any(x['cleanup_failed'] for x in leaves))
    _write(output / 'batch.json', _encode(result))
    try:
        (output / 'INCOMPLETE').unlink()
    except OSError:
        raise LiveError('output_error') from None
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Collect bounded Wazuh Indexer evidence (read-only).')
    parser.add_argument('--index', required=True)
    parser.add_argument('--agent', required=True)
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    parser.add_argument('--environment', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--collection-mode', choices=['direct', 'forwarded', 'unknown'], default='unknown')
    parser.add_argument('--adaptive', action='store_true', help='Split only record overflow into bounded, separate collections')
    args = parser.parse_args(argv)
    try:
        config = Config(endpoint=os.environ.get('WAZUH_INDEXER_URL', ''),
                        username=os.environ.get('WAZUH_INDEXER_USERNAME', ''),
                        password=os.environ.get('WAZUH_INDEXER_PASSWORD', ''),
                        ca_file=os.environ.get('WAZUH_INDEXER_CA_FILE') or None,
                        index=args.index, agent_id=args.agent, start=args.start, end=args.end,
                        environment_id=args.environment, collection_mode=args.collection_mode)
        result = (collect_adaptive if args.adaptive else collect)(config, args.output)
        print(json.dumps({key: result[key] for key in ('record_count', 'query_complete', 'collection_assurance', 'cleanup_failed')}))
        return 0
    except LiveError as error:
        print(json.dumps({'error': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
