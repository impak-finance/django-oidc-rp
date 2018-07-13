"""
    OpenID Connect relying party (RP) context processors
    =====================================================

    This module defines context processors related to the use of OpenID Connect for relying parties.

"""

import uuid
from hashlib import md5, sha224, sha256

from django.contrib.sites.requests import RequestSite

from .conf import settings as oidc_rp_settings


_anonymous_session_state = None


def oidc(request):
    """ Inserts OIDC-related values into the context. """
    global _anonymous_session_state

    if _anonymous_session_state is None and oidc_rp_settings.UNAUTHENTICATED_SESSION_MANAGEMENT_KEY:
        salt = md5(uuid.uuid4().hex.encode()).hexdigest()
        browser_state = sha224(
            oidc_rp_settings.UNAUTHENTICATED_SESSION_MANAGEMENT_KEY.encode('utf-8')).hexdigest()
        session_state = '{client_id} {origin} {browser_state} {salt}'.format(
            client_id=oidc_rp_settings.CLIENT_ID,
            origin='{}://{}'.format(request.scheme, RequestSite(request).domain),
            browser_state=browser_state, salt=salt)
        _anonymous_session_state = sha256(session_state.encode('utf-8')).hexdigest() + '.' + salt

    return {
        'oidc_op_url': oidc_rp_settings.PROVIDER_URL,
        'oidc_op_endpoint': oidc_rp_settings.PROVIDER_ENDPOINT,
        'oidc_client_id': oidc_rp_settings.CLIENT_ID,
        'oidc_anonymous_session_state': _anonymous_session_state,
    }
