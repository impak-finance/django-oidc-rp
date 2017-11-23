"""
    Development Django settings
    ===========================

    This file imports the ``base`` settings and can add or modify previously defined settings to
    alter the configuration of the application for development purposes.

    For more information on this file, see https://docs.djangoproject.com/en/dev/topics/settings/
    For the full list of settings and their values, see
    https://docs.djangoproject.com/en/dev/ref/settings/

"""

from .base import *  # noqa: F403


# DEBUG CONFIGURATION
# ------------------------------------------------------------------------------

DEBUG = True


# GENERAL CONFIGURATION
# ------------------------------------------------------------------------------

INTERNAL_IPS = ['127.0.0.1', ]
ADMINS = ()
MANAGERS = ()


# TEMPLATE CONFIGURATION
# ------------------------------------------------------------------------------

TEMPLATES[0]['OPTIONS']['loaders'] = (  # noqa: F405
    # Disables cached loader if any
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)


# STATIC FILE CONFIGURATION
# ------------------------------------------------------------------------------

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'


# ENV-SPECIFIC CONFIGURATION
# ------------------------------------------------------------------------------

try:
    # Allow the use of a settings module named "settings_env" that is not contributed to the
    # repository (only when dev settings are in use!).
    from .settings_env import *  # noqa
except ImportError:
    pass
