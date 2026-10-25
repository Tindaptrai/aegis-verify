from django.urls import path
from . import views

human_urls = [path("devices", views.devices), path("pairing-codes", views.pairing_codes),
              path("pairing-codes/<uuid:code_id>/revoke", views.pairing_code_revoke),
              path("devices/<uuid:device_id>/revoke", views.device_revoke)]
machine_urls = [path("enroll", views.enroll), path("heartbeat", views.heartbeat),
                path("network-heartbeat", views.network_heartbeat)]

human_v2_urls = [path("devices", views.devices_v2),
                 path("devices/<str:device_id>", views.device_detail),
                 path("devices/<str:device_id>/history", views.device_history),
                 path("devices/<str:device_id>/archive", views.device_archive)]
