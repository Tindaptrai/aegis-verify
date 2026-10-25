from django.urls import path
from . import views

urlpatterns = [
    path('catalog', views.catalog_list),
    path('catalog/import', views.catalog_import),
    path('catalog/<uuid:package_id>', views.catalog_detail),
    path('catalog/<uuid:package_id>/file', views.catalog_file),
    path('catalog/<uuid:package_id>/publish', views.catalog_lifecycle, {'publishing': True}),
    path('catalog/<uuid:package_id>/unpublish', views.catalog_lifecycle, {'publishing': False}),
]
