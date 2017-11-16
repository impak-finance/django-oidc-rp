"""
    OpenID Connect relying party (RP) settings
    ==========================================

    This file defines settings that can be overriden in the Django project's settings module.

"""

from urllib.parse import urljoin

from django.conf import settings


# The 'PROVIDER_ENDPOINT' setting defines the top-level endpoint under which all OIDC-specific
# endpoints are available (eg. 'authorize', 'token', 'userinfo'). These specific endpoints can be
# explicitely specified if necessary.
PROVIDER_ENDPOINT = getattr(settings, 'OIDC_RP_PROVIDER_ENDPOINT', 'https://example.com/a/')
PROVIDER_AUTHORIZATION_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_AUTHORIZATION_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'authorize'))
PROVIDER_TOKEN_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_TOKEN_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'token'))
PROVIDER_USERINFO_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_USERINFO_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'userinfo'))

# The 'CLIENT_ID' and 'CLIENT_SECRET' settings define the client_id / client_secret values provided
# by the OpenID Connect provider.
CLIENT_ID = getattr(settings, 'OIDC_RP_CLIENT_ID', None)
CLIENT_SECRET = getattr(settings, 'OIDC_RP_CLIENT_SECRET', None)

# The 'STATE_SIZE' setting defines the length of the opaque value used to maintain state between the
# authentication request and the callback. It is notably usefull to mitigate Cross-Site Request
# Forgery (CSRF, XSRF) by cryptographically binding the value with a cookie / a session key.
STATE_LENGTH = getattr(settings, 'OIDC_RP_STATE_LENGTH', 32)

# The 'SCOPES' setting defines the OpenID Connect scopes to request during login.
SCOPES = getattr(settings, 'OIDC_RP_SCOPES', 'openid email')

# The 'USE_NONCE' setting defines whether or not nonces should be used when forging authorization
# requests. Nonces are used to mitigate replay attacks.
USE_NONCE = getattr(settings, 'OIDC_RP_USE_NONCE', True)

# The 'NONCE_LENGTH' setting defines the length of the nonce used to mitigate replay attacks when
# used through the authentication request to the ID token.
NONCE_LENGTH = getattr(settings, 'OIDC_RP_NONCE_LENGTH', 32)
