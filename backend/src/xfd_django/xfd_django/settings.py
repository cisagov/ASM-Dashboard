"""
Django settings for xfd_django project.

Generated by 'django-admin startproject' using Django 4.2.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

# Standard Python Libraries
import os
import mimetypes

# Python built-in
from pathlib import Path

# Third-Party Libraries
from django.contrib.messages import constants as messages

mimetypes.add_type("text/css", ".css", True)
mimetypes.add_type("text/html", ".html", True)

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# TODO: GET THAT LATER
SECRET_KEY = os.getenv("DJANGO_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    ".execute-api.us-east-1.amazonaws.com",
    os.getenv('BACKEND_DOMAIN'),
    os.getenv('REACT_APP_API_URL'),
    os.getenv('FRONTEND_DOMAIN'),
]

MESSAGE_TAGS = {
    messages.DEBUG: "alert-secondary",
    messages.INFO: "alert-info",
    messages.SUCCESS: "alert-success",
    messages.WARNING: "alert-warning",
    messages.ERROR: "alert-danger",
}

# Application definition

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "xfd_api.apps.XfdApiConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": os.getenv('DB_NAME'),
        "USER": os.getenv('DB_USERNAME'),
        "PASSWORD": os.getenv('DB_PASSWORD'),
        "HOST": os.getenv('DB_HOST'),
        "PORT": "5432",
        'TEST': {
            'NAME': 'crossfeed_test',  # Name of the test database
        }
    }
}

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

PROJECT_NAME = "XFD Python API"

DJANGO_SETTINGS_MODULE = "xfd_django.settings"
