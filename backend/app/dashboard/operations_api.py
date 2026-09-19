"""Small metadata-only API; raw evidence has no HTTP route."""
import secrets

from ..intake.io import decode_config
from ..intake.errors import IntakeError
from .operations_config import OperationsError
from .operations_jobs import CollectionRequest
from .operations_security import authorize
from .operations_storage import valid_uuid
from . import operations_inventory


def error_response(code):
    status = {'forbidden': 403, 'not_found': 404, 'request_conflict': 409, 'job_busy': 409, 'refresh_busy': 409,
        'body_too_large': 413, 'unsupported_media': 415, 'rate_limited': 429,
        'not_configured': 503, 'storage_failed': 503, 'invalid_job_metadata': 503,
        'job_limit': 503, 'disk_space': 503, 'service_stopped': 503}.get(code, 400)
    return status, {'kind': 'error', 'error': {'code': code}}


class OperationsAPI:
    def __init__(self, config, jobs):
        self.config, self.jobs = config, jobs
        self.inventory = operations_inventory.InventoryService(config, fetch_fn=operations_inventory.fetch_agents)
        self.token = secrets.token_urlsafe(32)
        self.authority = None  # Set once to the actual bound address, including ephemeral test port.

    def authorize(self, method, path, headers):
        authorize(method, path, headers, authority=self.authority, token=self.token)

    def dispatch(self, method, path, headers, body):
        try:
            self.authorize(method, path, headers)
            if method == 'GET':
                if path == '/api/operations/bootstrap':
                    return 200, dict(environment_id=self.config.environment_id,
                        agent_ids=list(self.config.agent_ids), session_token=self.token,
                        capabilities={'collection': self.config.indexer is not None and not self.jobs.blocked_code,
                                      'inventory': self.config.server_api is not None}, error_code=self.jobs.blocked_code)
                if path == '/api/operations/agents':
                    return 200, self.inventory.snapshot()
                if path == '/api/operations/collections':
                    return 200, {'jobs': self.jobs.list_jobs(), 'error_code': self.jobs.blocked_code}
                prefix = '/api/operations/collections/'
                if path.startswith(prefix) and valid_uuid(path[len(prefix):]):
                    return 200, self.jobs.get_job(path[len(prefix):])
            elif method == 'POST':
                data = decode_config(body, stage='inputs')
                if path == '/api/operations/collections':
                    if set(data) != {'agent_id', 'start', 'end', 'adaptive', 'request_id'}:
                        raise OperationsError('invalid_request')
                    return 202, self.jobs.submit(CollectionRequest(**data))
                if path == '/api/operations/agents/refresh':
                    if data:
                        raise OperationsError('invalid_request')
                    return 202, self.inventory.refresh()
            raise OperationsError('not_found')
        except OperationsError as exc:
            return error_response(str(exc))
        except (IntakeError, TypeError, ValueError):
            return error_response('invalid_request')
