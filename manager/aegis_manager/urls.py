from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from accounts.shell import manager_shell
from devices.urls import human_urls, human_v2_urls, machine_urls
from control.execution_urls import human_urls as execution_human_urls, machine_urls as execution_machine_urls

urlpatterns = [path("", RedirectView.as_view(url="/manager/", permanent=False)),
               path("api/v1/connections/", include("connections.urls")),
               path("api/v1/", include(execution_human_urls)),
               path("agent/v2/execution/", include(execution_machine_urls)),
               path("manager/", manager_shell), path("admin/", admin.site.urls),
               path("agent/v1/", include("control.urls")), path("agent/v2/", include(machine_urls)),
               path("api/v2/", include(human_v2_urls)), path("api/v1/", include(human_urls)), path("api/v1/", include("accounts.urls")), path("api/v1/", include("catalog.urls"))]
