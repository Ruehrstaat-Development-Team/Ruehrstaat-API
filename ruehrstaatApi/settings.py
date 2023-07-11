from pathlib import Path
from configparser import ConfigParser

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

config = ConfigParser()
config.read("config.cfg")

WEBAPP_BRANCH = "BETA"
WEBAPP_VERSION = "1.2.0"

WEBAPP_NAME = config.get("CUSTOMIZATION", "WEBAPP_NAME")

WEBAPP_DOCUMENTATION_URL = config.get("CUSTOMIZATION", "WEBAPP_DOCUMENTATION_URL")

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config.get("GENERAL", "SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = bool(int(config.get("GENERAL", "DEBUG")))

ALLOWED_HOSTS = [config.get("GENERAL", "allowed_host")]


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "crispy_forms",
    "oauth2_provider",
    "rest_framework",
    "rest_framework_api_key",
    "backend.apps.BackendConfig",
    "carriers.apps.CarriersConfig",
    "api.apps.ApiConfig",
    "embeds.apps.EmbedsConfig",
    "webinterface.apps.WebinterfaceConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ruehrstaatApi.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "embeds.context_processors.webapp_version",
                "embeds.context_processors.webapp_name",
                "embeds.context_processors.webapp_branch",
            ],
        },
    },
]

WSGI_APPLICATION = "ruehrstaatApi.wsgi.application"

AUTH_USER_MODEL = "backend.User"

# change authentication backend
AUTHENTICATION_BACKENDS = [
    # standard django authentication
    "django.contrib.auth.backends.ModelBackend",
    # email authentication
    "backend.auth.EmailPasswordBackend",
    # discord authentication
    "backend.auth.DiscordBackend",
    # frontier authentication
    "backend.auth.FrontierBackend",
]


# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": config.get("DATABASE", "ENGINE"),
        "NAME": config.get("DATABASE", "NAME"),
        "USER": config.get("DATABASE", "USER"),
        "PASSWORD": config.get("DATABASE", "PASSWORD"),
        "HOST": config.get("DATABASE", "HOST"),
        "PORT": config.get("DATABASE", "PORT"),
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    },
}


# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_ROOT = BASE_DIR / "static/"
STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CRISPY_TEMPLATE_PACK = "bootstrap4"

LOGIN_REDIRECT_URL = "/"
LOGIN_URL = '/login/'
LOGOUT_REDIRECT_URL = "/login/"

EMAIL_BACKEND = config.get("EMAIL", "backend")
EMAIL_HOST = config.get("EMAIL", "host")
EMAIL_PORT = config.get("EMAIL", "port")
EMAIL_HOST_USER = config.get("EMAIL", "username")
EMAIL_HOST_PASSWORD = config.get("EMAIL", "password")
EMAIL_USE_SSL = bool(int(config.get("EMAIL", "use_ssl")))
DEFAULT_FROM_EMAIL = config.get("EMAIL", "default_from_email")
SERVER_EMAIL = config.get("EMAIL", "server_email")

# HTTPS Settings
CSRF_COOKIE_SECURE = bool(int(config.get("HTTPS", "csrf_cookie_secure")))
SESSION_COOKIE_SECURE = bool(int(config.get("HTTPS", "session_cookie_secure")))


REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "oauth2_provider.contrib.rest_framework.OAuth2Authentication",
        "rest_framework.authentication.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
}

# Oauth2 Settings
OAUTH2_PROVIDER = {
    "SCOPES": {"read": "Read scope", "write": "Write scope"},
}

# Dicord Authentication Settings

DISCORD_CLIENT_ID = config.get("DISCORDLOGIN", "client_id")
DISCORD_CLIENT_SECRET = config.get("DISCORDLOGIN", "client_secret")
