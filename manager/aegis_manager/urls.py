from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from accounts.shell import manager_shell
from devices.urls import human_urls, machine_urls

urlpatterns = [path("", RedirectView.as_view(url="/manager/", permanent=False)),
               path("manager/", manager_shell), path("admin/", admin.site.urls),
               path("agent/v1/", include("control.urls")), path("agent/v2/", include(machine_urls)),
               path("api/v1/", include(human_urls)), path("api/v1/", include("accounts.urls"))]
