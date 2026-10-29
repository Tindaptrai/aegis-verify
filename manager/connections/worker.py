"""Read-only registry waiter. Candidate metadata is never collection authority."""
import uuid
from .services import managed_candidate


class RegistryError(Exception):
    pass


def waiting_status():
    try:
        candidate = managed_candidate()
    except Exception:
        raise RegistryError('registry_unavailable') from None
    if candidate is None:
        return 'waiting_configuration:no_candidate'
    try:
        # Closed contract rejects future activation metadata until that feature
        # has a reviewed implementation. There is no active pointer in slice 1.
        if type(candidate) is not dict or set(candidate) != {
            'candidate_id', 'source_id', 'version', 'status', 'connection_id', 'connection_revision'
        }:
            raise ValueError
        if candidate['status'] != 'waiting_configuration':
            raise ValueError
        for name in ('candidate_id', 'source_id', 'connection_id'):
            value = candidate[name]
            if type(value) is not str or str(uuid.UUID(value)) != value:
                raise ValueError
        if type(candidate['version']) is not int or candidate['version'] < 1:
            raise ValueError
        if type(candidate['connection_revision']) is not int or candidate['connection_revision'] != 1:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise RegistryError('registry_invalid') from None
    return 'waiting_configuration:candidate_selected'
