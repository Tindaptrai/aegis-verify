from django.urls import path
from . import views

urlpatterns = [path('',views.sources), path('wazuh/test',views.test_wazuh),
               path('wazuh/save',views.save_wazuh), path('<uuid:source_id>/prepare',views.prepare)]
