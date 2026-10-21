"""Ephemeral CI PostgreSQL only. Never use these settings for a lab deployment."""
import os
from django.core.exceptions import ImproperlyConfigured
from .test_settings import *

if os.environ.get('AEGIS_MANAGER_CI') != '1':
    raise ImproperlyConfigured('CI settings require the isolated CI test environment')

DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql',
    'NAME': os.environ['AEGIS_MANAGER_DB_NAME'], 'USER': os.environ['AEGIS_MANAGER_DB_USER'],
    'PASSWORD': os.environ['AEGIS_MANAGER_DB_PASSWORD'], 'HOST': os.environ['AEGIS_MANAGER_DB_HOST'],
    'PORT': os.environ['AEGIS_MANAGER_DB_PORT']}}
