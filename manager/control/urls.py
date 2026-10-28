from django.urls import path
from .views import endpoint
urlpatterns = [path("poll",endpoint), path("jobs/<uuid:job_id>/start",endpoint,{"operation":"start"}), path("jobs/<uuid:job_id>/receipt",endpoint,{"operation":"receipt"})]
