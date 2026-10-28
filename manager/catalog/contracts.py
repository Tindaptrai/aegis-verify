from accounts.contracts import parse_json
from .errors import CatalogError


def stamp(value):
    return value.isoformat().replace('+00:00', 'Z') if value is not None else None


def package_dto(row, *, detail=False):
    result = {key: row.metadata[key] for key in ('name', 'platform', 'runner', 'timeout_seconds')}
    result.update(id=str(row.pk), scenario_id=row.scenario_id, version=row.version, sha256=row.sha256,
        status=row.status, created_at=stamp(row.created_at), created_by=row.created_by.username if row.created_by else None,
        published_at=stamp(row.published_at), published_by=row.published_by.username if row.published_by else None)
    if detail:
        recent = list(row.audit.select_related('actor').order_by('-pk')[:100])
        result.update(validation=row.validation, files=row.files, execution_supported=False,
            audit=[{'action': item.action, 'actor': item.actor.username if item.actor else None, 'at': stamp(item.at)} for item in reversed(recent)])
    return result


def list_query(request):
    if set(request.GET) - {'page', 'q', 'status'} or any(len(values) != 1 for _, values in request.GET.lists()):
        raise CatalogError('invalid_request')
    page = request.GET.get('page', '1')
    query, status = request.GET.get('q', ''), request.GET.get('status', '')
    if not page.isascii() or not page.isdigit() or len(page) > 9 or int(page) < 1 or len(query) > 200 or status not in ('', 'draft', 'published', 'unpublished'):
        raise CatalogError('invalid_request')
    return int(page), query, status


def digest_input(request):
    data = parse_json(request)
    if set(data) != {'sha256'}:
        raise CatalogError('invalid_request')
    return data['sha256']
