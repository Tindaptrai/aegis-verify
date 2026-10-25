from functools import wraps
from django.core.exceptions import RequestDataTooBig, TooManyFilesSent, TooManyFieldsSent
from django.db.models import Q
from django.http import JsonResponse
from accounts.permissions import require_product_permission
from accounts.views import api_error, human_api
from .contracts import digest_input, list_query, package_dto
from .errors import CatalogError
from .models import ScenarioPackageVersion
from .services import get_package, import_package, publish_package, unpublish_package
from .storage import verify


def catalog_api(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        try:
            return view(request, *args, **kwargs)
        except CatalogError as error:
            body = {'error': {'code': error.code}}
            if error.codes and error.code not in {'version_conflict', 'content_conflict', 'package_not_found', 'storage_unavailable', 'invalid_request'}:
                body['validation'] = {'valid': False, 'codes': list(error.codes)}
            response = JsonResponse(body, status=error.status)
            response['Cache-Control'] = 'no-store'
            return response
        except (RequestDataTooBig, TooManyFilesSent, TooManyFieldsSent):
            return api_error('invalid_request', 400)
    return wrapped


@catalog_api
@human_api('GET', authenticated=True)
def catalog_list(request):
    require_product_permission(request.user, 'view')
    page, query, status = list_query(request)
    rows = ScenarioPackageVersion.objects.select_related('created_by', 'published_by')
    if query:
        rows = rows.filter(Q(scenario_id__icontains=query) | Q(metadata__name__icontains=query))
    if status:
        rows = rows.filter(status=status)
    offset = (page - 1) * 50
    return JsonResponse({'results': [package_dto(row) for row in rows.order_by('-created_at', 'pk')[offset:offset + 50]], 'count': rows.count(), 'page': page, 'page_size': 50})


@catalog_api
@human_api('POST', authenticated=True)
def catalog_import(request):
    require_product_permission(request.user, 'import_scenarios')
    if request.content_type != 'multipart/form-data' or request.POST or set(request.FILES) != {'package'} or len(request.FILES.getlist('package')) != 1:
        raise CatalogError('invalid_request')
    row, created = import_package(actor=request.user, stream=request.FILES['package'])
    return JsonResponse(package_dto(row, detail=True), status=201 if created else 200)


@catalog_api
@human_api('GET', authenticated=True)
def catalog_detail(request, package_id):
    require_product_permission(request.user, 'view')
    row = get_package(package_id)
    verify(row)
    return JsonResponse(package_dto(row, detail=True))


@catalog_api
@human_api('GET', authenticated=True)
def catalog_file(request, package_id):
    require_product_permission(request.user, 'view')
    if set(request.GET) != {'path'} or len(request.GET.getlist('path')) != 1:
        raise CatalogError('invalid_request')
    package = verify(get_package(package_id))
    path = request.GET['path']
    if path not in package.contents:
        raise CatalogError('invalid_request')
    return JsonResponse({'path': path, 'text': package.contents[path].decode('utf-8')})


@catalog_api
@human_api('POST', authenticated=True)
def catalog_lifecycle(request, package_id, publishing):
    require_product_permission(request.user, 'publish_scenarios')
    service = publish_package if publishing else unpublish_package
    return JsonResponse(package_dto(service(actor=request.user, package_id=package_id, sha256=digest_input(request)), detail=True))
