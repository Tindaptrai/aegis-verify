"""Bounded private job metadata persistence; never stores credentials or raw events."""
import json
import os
from pathlib import Path
import re
import tempfile
from uuid import UUID

from ..intake.io import decode_config, read_local
from ..intake.errors import IntakeError
from ..models import PreciseTimestamp
from .operations_config import OperationsError, local_path

ERROR_CODES = frozenset({'interrupted', 'collection_failed', 'incomplete_collection',
    'authentication_failed', 'permission_denied', 'rate_limited', 'connection_or_tls_failed',
    'invalid_ca', 'record_limit', 'count_limit_or_mismatch', 'cleanup_failed',
    'storage_failed', 'collection_deadline', 'collection_byte_limit', 'adaptive_limit'})
JOB_KEYS = frozenset({'id', 'request_id', 'agent_id', 'start', 'end', 'adaptive',
    'state', 'created_at', 'finished_at', 'result', 'error_code'})


def valid_uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def validate_record(record):
    try:
        if (type(record) is not dict or record.keys() != JOB_KEYS
                or not valid_uuid(record['id']) or not valid_uuid(record['request_id'])
                or type(record['agent_id']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', record['agent_id'])
                or type(record['adaptive']) is not bool
                or record['state'] not in ('running', 'completed', 'failed', 'interrupted')):
            raise ValueError
        for key in ('start', 'end', 'created_at'):
            if type(record[key]) is not str:
                raise ValueError
            PreciseTimestamp.parse(record[key])
        if PreciseTimestamp.parse(record['start']) >= PreciseTimestamp.parse(record['end']):
            raise ValueError
        if record['state'] == 'running':
            if any(record[k] is not None for k in ('finished_at', 'result', 'error_code')):
                raise ValueError
        else:
            PreciseTimestamp.parse(record['finished_at'])
            if record['state'] == 'completed':
                result = record['result']
                if (type(result) is not dict or set(result) != {'record_count', 'query_complete',
                        'collection_assurance', 'cleanup_failed'} or type(result['record_count']) is not int
                        or not 0 <= result['record_count'] <= 6300 or result['query_complete'] is not True
                        or result['collection_assurance'] != 'unknown' or type(result['cleanup_failed']) is not bool
                        or record['error_code'] is not None):
                    raise ValueError
            elif record['result'] is not None or record['error_code'] not in ERROR_CODES:
                raise ValueError
    except (ValueError, TypeError, KeyError):
        raise OperationsError('invalid_job_metadata') from None


class JobStore:
    """Root must have passed owner-only preflight; a single JobService owns writes."""
    def __init__(self, root):
        self.root = local_path(root, directory=True)
        try:
            for name in ('metadata', 'jobs'):
                (self.root / name).mkdir(mode=0o700, exist_ok=True)
                local_path(self.root / name, directory=True)
        except OSError:
            raise OperationsError('storage_failed') from None

    def load(self):
        result = []
        requests = set()
        try:
            directory = local_path(self.root / 'metadata', directory=True)
            for path in directory.iterdir():
                if len(result) >= 100 or path.suffix != '.json' or not valid_uuid(path.stem):
                    raise OperationsError('invalid_job_metadata')
                if local_path(path).stat().st_nlink != 1:
                    raise OperationsError('invalid_job_metadata')
                record = decode_config(read_local(path, limit=16384, stage='inputs'), stage='inputs')
                validate_record(record)
                if record['id'] != path.stem or record['request_id'] in requests:
                    raise OperationsError('invalid_job_metadata')
                requests.add(record['request_id'])
                result.append(record)
        except (OSError, IntakeError):
            raise OperationsError('invalid_job_metadata') from None
        return sorted(result, key=lambda item: item['created_at'])

    def save(self, record):
        validate_record(record)
        existing = self.load()
        if len(existing) >= 100 and record['id'] not in {r['id'] for r in existing}:
            raise OperationsError('job_limit')
        if any(r['request_id'] == record['request_id'] and r['id'] != record['id'] for r in existing):
            raise OperationsError('invalid_job_metadata')
        raw = json.dumps(record, allow_nan=False).encode('utf-8')
        if len(raw) > 16384:
            raise OperationsError('invalid_job_metadata')
        temporary = None
        try:
            directory = local_path(self.root / 'metadata', directory=True)
            # Temporary files are not valid jobs: crash remnants fail closed at next load.
            fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, directory / (record['id'] + '.json'))
            temporary = None
        except OSError:
            raise OperationsError('storage_failed') from None
        finally:
            if temporary is not None:
                try:
                    Path(temporary).unlink()
                except OSError:
                    pass

    def new_output(self, job_id):
        if not valid_uuid(job_id):
            raise OperationsError('invalid_job_metadata')
        try:
            parent = local_path(self.root / 'jobs', directory=True)
            path = parent / job_id
            path.mkdir(mode=0o700, exist_ok=False)
            return path
        except OSError:
            raise OperationsError('storage_failed') from None
