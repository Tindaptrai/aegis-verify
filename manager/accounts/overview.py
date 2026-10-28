"""Read-only registration counts; these do not imply live device presence."""
from django.http import JsonResponse

from control.models import Device, Job, RunnerRelease
from .permissions import require_product_permission
from .views import human_api


@human_api("GET", authenticated=True)
def overview(request):
    require_product_permission(request.user, "view")
    return JsonResponse({"registered_devices": Device.objects.count(),
                         "recorded_jobs": Job.objects.count(),
                         "recorded_releases": RunnerRelease.objects.count()})
