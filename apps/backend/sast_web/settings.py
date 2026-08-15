from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

SECRET_KEY = os.environ.get("SAST_WEB_SECRET_KEY", "dev-only-change-me")
DEBUG = os.environ.get("SAST_WEB_DEBUG", "1") == "1"
ALLOWED_HOSTS = os.environ.get("SAST_WEB_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "scans",
]

MIDDLEWARE = [
    "sast_web.middleware.SimpleCorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "sast_web.urls"
WSGI_APPLICATION = "sast_web.wsgi.application"
ASGI_APPLICATION = "sast_web.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
MEDIA_ROOT = BASE_DIR / "media"
MEDIA_URL = "media/"

SAST_REPO_ROOT = REPO_ROOT
SAST_CONFIG_PATH = REPO_ROOT / "configs" / "scanner.yaml"
SAST_WEB_REPORT_ROOT = REPO_ROOT / "reports"
SAST_WEB_UPLOAD_ROOT = BASE_DIR / "media" / "uploads"
SAST_WEB_MAX_UPLOAD_BYTES = int(os.environ.get("SAST_WEB_MAX_UPLOAD_BYTES", str(250 * 1024 * 1024)))
SAST_WEB_CORS_ORIGINS = os.environ.get("SAST_WEB_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
