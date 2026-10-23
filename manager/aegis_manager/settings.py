import os
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured
from .base import *


def required(name):
    value = os.environ.get(name)
    if not value: raise ImproperlyConfigured(name + " is required")
    return value


SECRET_KEY = required("AEGIS_MANAGER_SECRET_KEY")
if len(SECRET_KEY) < 50: raise ImproperlyConfigured("Use a private random secret key")
ALLOWED_HOSTS = [value.strip() for value in required("AEGIS_MANAGER_ALLOWED_HOSTS").split(",") if value.strip()]
if not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS: raise ImproperlyConfigured("Explicit allowed hosts required")
PRIVATE_ROOT = Path(required("AEGIS_MANAGER_PRIVATE_ROOT")).resolve()
CHECKOUT_ROOT = Path(__file__).resolve().parents[2]
if not PRIVATE_ROOT.is_dir() or PRIVATE_ROOT.is_relative_to(CHECKOUT_ROOT): raise ImproperlyConfigured("Private directory must exist outside checkout")
MANAGER_SIGNING_KEY = str(Path(required("AEGIS_MANAGER_SIGNING_KEY")).resolve())
if not Path(MANAGER_SIGNING_KEY).is_file() or not Path(MANAGER_SIGNING_KEY).is_relative_to(PRIVATE_ROOT): raise ImproperlyConfigured("Signing key must be inside private directory")
# Enrollment setup is explicit and validated lazily, preserving v1 startup.
ENROLLMENT_CA_KEY = os.environ.get("AEGIS_MANAGER_ENROLLMENT_CA_KEY") or str(PRIVATE_ROOT / "enrollment-ca-key.pem")
ENROLLMENT_CA_CERT = os.environ.get("AEGIS_MANAGER_ENROLLMENT_CA_CERT") or str(PRIVATE_ROOT / "enrollment-ca.pem")
DATABASES = {"default": {"ENGINE":"django.db.backends.postgresql", "NAME":required("AEGIS_MANAGER_DB_NAME"), "USER":required("AEGIS_MANAGER_DB_USER"), "PASSWORD":required("AEGIS_MANAGER_DB_PASSWORD"), "HOST":required("AEGIS_MANAGER_DB_HOST"), "PORT":required("AEGIS_MANAGER_DB_PORT"), "CONN_MAX_AGE":60}}
DEBUG = False
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

STATIC_ROOT = str(PRIVATE_ROOT / "static")
# Trusted, read-only standalone Manager build. No dashboard/private fallback.
MANAGER_UI_ROOT = os.environ.get("AEGIS_MANAGER_UI_ROOT") or None
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
