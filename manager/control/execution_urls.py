from django.urls import path
from . import execution_views as views

human_urls=[
    path('execution/providers',views.providers),
    path('execution/devices/<uuid:device_id>',views.device),
    path('execution/devices/<uuid:device_id>/binding',views.binding),
    path('jobs/preview',views.preview), path('jobs/approve',views.approve),
    path('jobs/current',views.current_job),
    path('jobs/<uuid:job_id>',views.job), path('jobs/<uuid:job_id>/cancel',views.cancel),
]
machine_urls=[
    path('readiness',views.machine,{'operation':'readiness'}),
    path('poll',views.machine,{'operation':'poll'}),
    path('jobs/<uuid:job_id>/start',views.machine,{'operation':'start'}),
    path('receipt',views.machine,{'operation':'receipt'}),
]
