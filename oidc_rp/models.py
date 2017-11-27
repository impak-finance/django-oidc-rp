"""
    OpenID Connect relying party (RP) models
    ========================================

    This modules defines models allowing to manage users authenticated using an OpenID Connect
    Provider (OP). Precisely it defines an OpenID Connect user associated with the user table that
    defines a sub field allowing to uniquely identify users authenticated using the OIDC provider.

"""

from django.conf import settings
from django.db import models
from django.utils.translation import ugettext_lazy as _
from jsonfield import JSONField


class OIDCUser(models.Model):
    """ Represents a user managed by an OpenID Connect provider (OP). """

    # An OpenID Connect user is associated with a record in the main user table.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='oidc_user')

    # The 'sub' value (aka Subject Identifier) is a locally unique and never reassigned identifier
    # within the issuer for the end-user. It is intended to be consumed by relying parties and does
    # not change over time. It corresponds to the only way to uniquely identify users between OIDC
    # provider and relying parties.
    sub = models.CharField(max_length=255, unique=True, verbose_name=_('Subject identifier'))

    # The content of the userinfo response will be stored in the following field.
    userinfo = JSONField(verbose_name=_('Subject extra data'))

    class Meta:
        verbose_name = _('OpenID Connect user')
        verbose_name_plural = _('OpenID Connect users')

    def __str__(self):
        return str(self.user)
