"""
    OpenID Connect relying party (RP) settings
    ==========================================

    This file defines settings that can be overriden in the Django project's settings module.

"""

from urllib.parse import urljoin, urlparse

from django.conf import settings


# The 'PROVIDER_ENDPOINT' setting defines the top-level endpoint under which all OIDC-specific
# endpoints are available (eg. 'authorize', 'token', 'userinfo', ...). These specific endpoints can
# be explicitely specified if necessary.
PROVIDER_ENDPOINT = getattr(settings, 'OIDC_RP_PROVIDER_ENDPOINT', 'https://example.com/a/')

_parsed_provider_endpoint = urlparse(PROVIDER_ENDPOINT)
PROVIDER_URL = '{}://{}'.format(_parsed_provider_endpoint.scheme, _parsed_provider_endpoint.netloc)

PROVIDER_AUTHORIZATION_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_AUTHORIZATION_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'authorize'))
PROVIDER_TOKEN_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_TOKEN_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'token'))
PROVIDER_JWKS_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_JWKS_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'jwks'))
PROVIDER_USERINFO_ENDPOINT = getattr(
    settings, 'OIDC_RP_PROVIDER_USERINFO_ENDPOINT', urljoin(PROVIDER_ENDPOINT, 'userinfo'))
PROVIDER_END_SESSION_ENDPOINT = getattr(settings, 'OIDC_RP_PROVIDER_END_SESSION_ENDPOINT', None)

# The 'PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER' setting defines which URI should be passed to
# the end-session endpoint of the OpenID Connect provider in order to redirect the end-user back to
# the client application after a logout operation. The 'PROVIDER_END_SESSION_ID_TOKEN_PARAMETER'
# defines the name of the GET parameter used to pass the ID token to the provider's endpoint as a
# hint about the end-user's current session with the client.
PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER = getattr(
    settings, 'OIDC_RP_PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER', 'post_logout_redirect_uri')
PROVIDER_END_SESSION_ID_TOKEN_PARAMETER = getattr(
    settings, 'OIDC_RP_PROVIDER_END_SESSION_ID_TOKEN_PARAMETER', 'id_token_hint')

# The signature algorithm used by the OpenID Connect Provider to sign ID tokens. The value should be
# 'HS256' or 'RS256'.
PROVIDER_SIGNATURE_ALG = getattr(settings, 'OIDC_RP_PROVIDER_SIGNATURE_ALG', 'HS256')
PROVIDER_SIGNATURE_KEY = getattr(settings, 'OIDC_RP_PROVIDER_SIGNATURE_KEY', None)

# The 'CLIENT_ID' and 'CLIENT_SECRET' settings define the client_id / client_secret values provided
# by the OpenID Connect provider.
CLIENT_ID = getattr(settings, 'OIDC_RP_CLIENT_ID', None)
CLIENT_SECRET = getattr(settings, 'OIDC_RP_CLIENT_SECRET', None)

# The 'USE_STATE' settings defines whether or not states should be used in the authentication flow.
# The state value is a recommended one (it is not required by the OpenID Connect specification). It
# is used to maintain state between the authentication request and the callback.
USE_STATE = getattr(settings, 'OIDC_RP_USE_STATE', True)

# The 'STATE_LENGTH' setting defines the length of the opaque value used to maintain state between
# the authentication request and the callback. It is notably usefull to mitigate Cross-Site Request
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

# The 'ID_TOKEN_MAX_AGE' setting defines the amount of time an id_token should be considered a
# valid token.
ID_TOKEN_MAX_AGE = getattr(settings, 'OIDC_RP_ID_TOKEN_MAX_AGE', 600)

# The 'ID_TOKEN_INCLUDE_USERINFO' setting defines whether or not the id_token contains the userinfo
# related claims (associated with the requested scopes).
ID_TOKEN_INCLUDE_USERINFO = getattr(settings, 'OIDC_RP_ID_TOKEN_INCLUDE_USERINFO', False)

# The 'AUTHENTICATION_REDIRECT_URI' setting defines the URI that should be used to redirect the
# end-user after a successful authentication performed by the OIDC provider if the view gets no
# "next" parameter.
AUTHENTICATION_REDIRECT_URI = getattr(settings, 'OIDC_RP_AUTHENTICATION_REDIRECT_URI', '/')

# The 'AUTHENTICATION_FAILURE_REDIRECT_URI' setting defines the URI that should be used to redirect
# the end-user after a failed authentication.
AUTHENTICATION_FAILURE_REDIRECT_URI = getattr(
    settings, 'OIDC_RP_AUTHENTICATION_FAILURE_REDIRECT_URI', '/')

# The 'USER_DETAILS_HANDLER' setting defines a path towards a function that should be executed each
# time users sign in (or sign up) to the application using OpenID Connect. The considered function
# takes the OpenID Connect user instance and the claims dictionary as main arguments. It should be
# responsible for creating whatever is necessary to manage the user later on.
USER_DETAILS_HANDLER = getattr(settings, 'OIDC_RP_USER_DETAILS_HANDLER', None)

# The 'UNAUTHENTICATED_SESSION_MANAGEMENT_KEY' settings defines a fixed string to use as a
# browser-state key for unauthenticated clients. It can be usefull to define this value when it
# comes to supporting the OpenID Connect Session Management 1.0 specification. Authenticated users
# are associated with a session state which is generated by the OpenID Connect Provider but this is
# not the case for anonymous users. This is why this key should be defined on the OP level and on
# Relying Party. The session_state value for anonymous users will be computed by using this key.
UNAUTHENTICATED_SESSION_MANAGEMENT_KEY = getattr(
    settings, 'OIDC_RP_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY', None)
