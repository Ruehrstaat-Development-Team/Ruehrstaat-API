from pathlib import Path
from configparser import ConfigParser
import json

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

config = ConfigParser()
config.read('config.cfg')

WEBAPP_BRANCH = "BETA"
WEBAPP_VERSION = "0.1.4"

WEBAPP_NAME = config.get('CUSTOMIZATION', 'WEBAPP_NAME')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config.get('GENERAL', 'SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = bool(int(config.get('GENERAL', 'DEBUG')))

ALLOWED_HOSTS = [config.get('GENERAL', 'allowed_host')]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'crispy_forms',
    'rest_framework',
    'rest_framework_api_key',
    'carriers.apps.CarriersConfig',
    'api.apps.ApiConfig',
    'embeds.apps.EmbedsConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ruehrstaatApi.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'embeds.context_processors.webapp_version',
                'embeds.context_processors.webapp_name',
                'embeds.context_processors.webapp_branch',
            ],
        },
    },
]

WSGI_APPLICATION = 'ruehrstaatApi.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': config.get('DATABASE', 'ENGINE'),
        'NAME': config.get('DATABASE', 'NAME'),
        'USER': config.get('DATABASE', 'USER'),
        'PASSWORD': config.get('DATABASE', 'PASSWORD'),
        'HOST': config.get('DATABASE', 'HOST'),
        'PORT': config.get('DATABASE', 'PORT'),
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        }
    },
}


# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_ROOT = BASE_DIR / 'static/'
STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CRISPY_TEMPLATE_PACK = 'bootstrap4'

LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

EMAIL_BACKEND = config.get('EMAIL', 'backend')
EMAIL_HOST = config.get('EMAIL', 'host')
EMAIL_PORT = config.get('EMAIL', 'port')
EMAIL_HOST_USER = config.get('EMAIL', 'username')
EMAIL_HOST_PASSWORD = config.get('EMAIL', 'password')
EMAIL_USE_SSL = bool(int(config.get('EMAIL', 'use_ssl')))
DEFAULT_FROM_EMAIL = config.get('EMAIL', 'default_from_email')
SERVER_EMAIL = config.get('EMAIL', 'server_email')

# HTTPS Settings
CSRF_COOKIE_SECURE = bool(int(config.get('HTTPS', 'csrf_cookie_secure')))
SESSION_COOKIE_SECURE = bool(int(config.get('HTTPS', 'session_cookie_secure')))


REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    )
}

