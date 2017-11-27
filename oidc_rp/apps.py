"""
    OpenID Connect relying party (RP) app config
    ============================================

    This module contains the application configuration class - available in the Django app registry.
    For more information on this file, see https://docs.djangoproject.com/en/dev/ref/applications/

"""

from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class OIDCRelyingPartyAppConfig(AppConfig):
    label = 'oidc_rp'
    name = 'oidc_rp'
    verbose_name = _('OpenID Connect relying party')
