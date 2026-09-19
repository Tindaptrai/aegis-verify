"""Single worker orchestration; collection results are not security verdicts."""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import re
import shutil
from threading import RLock, Thread
from uuid import uuid4

from ..models import PreciseTimestamp
from ..connectors.wazuh.live import Config, LiveError, collect, collect_adaptive
from .operations_config import OperationsError
from .operations_storage import ERROR_CODES, valid_uuid, validate_record


@dataclass(frozen=True)
class CollectionRequest:
    agent_id: str
    start: str
    end: str
    adaptive: bool
    request_id: str

    def __post_init__(self):
        try:
            if (type(self.agent_id) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', self.agent_id)
                    or type(self.adaptive) is not bool or not valid_uuid(self.request_id)
                    or type(self.start) is not str or type(self.end) is not str
                    or not self.start.endswith(('Z', '+00:00')) or not self.end.endswith(('Z', '+00:00'))
                    or PreciseTimestamp.parse(self.start) >= PreciseTimestamp.parse(self.end)):
                raise ValueError
        except (ValueError, TypeError):
            raise OperationsError('invalid_request') from None


def _collect(config, output, *, adaptive):
    return (collect_adaptive if adaptive else collect)(config, output)


class JobService:
    def __init__(self, config, store, *, collect_fn=_collect,
                 now=lambda: datetime.now(timezone.utc),
                 free_bytes=lambda path: shutil.disk_usage(path).free):
        self.config, self.store = config, store
        self._collect, self._now, self._free = collect_fn, now, free_bytes
        self._lock = RLock()
        self._worker = None
        self._closed = False
        self._blocked = None
        self._jobs = {}
        try:
            for job in store.load():
                if job['state'] == 'running':
                    job.update(state='interrupted', finished_at=self._stamp(), error_code='interrupted')
                    store.save(job)
                self._jobs[job['id']] = job
        except OperationsError as exc:
            self._blocked = str(exc)

    def _stamp(self):
        return PreciseTimestamp.parse(self._now()).isoformat()

    @property
    def blocked_code(self):
        return self._blocked

    def list_jobs(self):
        with self._lock:
            return deepcopy(list(self._jobs.values()))

    def get_job(self, job_id):
        with self._lock:
            if job_id not in self._jobs:
                raise OperationsError('not_found')
            return deepcopy(self._jobs[job_id])

    def submit(self, request):
        with self._lock:
            if self._blocked:
                raise OperationsError(self._blocked)
            if self._closed:
                raise OperationsError('service_stopped')
            if self.config.indexer is None:
                raise OperationsError('not_configured')
            if not isinstance(request, CollectionRequest) or request.agent_id not in self.config.agent_ids:
                raise OperationsError('invalid_request')
            start, end = PreciseTimestamp.parse(request.start), PreciseTimestamp.parse(request.end)
            if end > PreciseTimestamp.parse(self._now()) or end.difference_ns(start) > 86400 * 10**9:
                raise OperationsError('invalid_window')
            for job in self._jobs.values():
                if job['request_id'] == request.request_id:
                    if any(job[key] != getattr(request, key) for key in ('agent_id', 'start', 'end', 'adaptive')):
                        raise OperationsError('request_conflict')
                    return deepcopy(job)
            if self._worker is not None and self._worker.is_alive():
                raise OperationsError('job_busy')
            if len(self._jobs) >= 100:
                raise OperationsError('job_limit')
            try:
                if self._free(self.config.output_root) < 2 * 1024**3:
                    raise OperationsError('disk_space')
            except OSError:
                raise OperationsError('storage_failed') from None
            identifier = str(uuid4())
            job = dict(id=identifier, request_id=request.request_id, agent_id=request.agent_id,
                start=request.start, end=request.end, adaptive=request.adaptive, state='running',
                created_at=self._stamp(), finished_at=None, result=None, error_code=None)
            self.store.save(job)  # Persist intent before filesystem allocation or source request.
            self._jobs[identifier] = job
            try:
                output = self.store.new_output(identifier) / 'bundle'
                self._worker = Thread(target=self._run, args=(identifier, output), daemon=False)
                self._worker.start()
            except (OperationsError, RuntimeError):
                self._finish(identifier, None, 'storage_failed')
                raise OperationsError('storage_failed') from None
            return deepcopy(job)

    def _finish(self, identifier, result, error):
        with self._lock:
            updated = {**self._jobs[identifier], 'state': 'failed' if error else 'completed',
                       'result': result, 'error_code': error, 'finished_at': self._stamp()}
            try:
                self.store.save(updated)
            except OperationsError:
                self._blocked = 'storage_failed'
                updated.update(state='failed', result=None, error_code='storage_failed')
            self._jobs[identifier] = updated

    def _run(self, identifier, output):
        job = self.get_job(identifier)
        connection = self.config.indexer
        result, error = None, None
        try:
            cfg = Config(endpoint=connection.endpoint, username=connection.username,
                password=connection.password, ca_file=str(connection.ca_file), index=self.config.index,
                agent_id=job['agent_id'], start=job['start'], end=job['end'],
                environment_id=self.config.environment_id)
            summary = self._collect(cfg, output, adaptive=job['adaptive'])
            if type(summary) is not dict or summary.get('query_complete') is not True:
                raise OperationsError('incomplete_collection')
            result = {key: summary[key] for key in ('record_count', 'query_complete',
                                                   'collection_assurance', 'cleanup_failed')}
            validate_record({**job, 'state': 'completed', 'result': result, 'finished_at': self._stamp()})
        except LiveError as exc:
            error = str(exc) if str(exc) in ERROR_CODES else 'collection_failed'
        except OperationsError as exc:
            error = 'incomplete_collection' if str(exc) == 'incomplete_collection' else 'collection_failed'
        except Exception:
            error = 'collection_failed'
        self._finish(identifier, None if error else result, error)

    def shutdown(self):
        with self._lock:
            self._closed = True
            worker = self._worker
        if worker is not None:
            worker.join()  # Collector controls its bounded requests/attempts; never cancel mid-write.
