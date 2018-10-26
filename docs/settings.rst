########
Settings
########

This is a comprehensive list of all the settings provided by django-oidc-rp.

Required settings
=================

``OIDC_RP_PROVIDER_ENDPOINT``
-----------------------------

This setting defines the top-level endpoint under which all OIDC-specific endpoints are available
(such as the authotization, token and userinfo endpoints).

Default: ``https://example.com/a/``

``OIDC_RP_CLIENT_ID``
---------------------

This setting defines the Client ID that should be provided by the considered OIDC provider.

Default: ``None``

``OIDC_RP_CLIENT_SECRET``
-------------------------

This setting defines the Client Secret that should be provided by the considered OIDC provider.

Default: ``None``

Optional settings
=================

``OIDC_RP_PROVIDER_AUTHORIZATION_ENDPOINT``
-------------------------------------------

This setting defines the authorization endpoint URL of the OIDC provider. Unless explicitely
defined, it is automatically generated from the ``OIDC_RP_PROVIDER_ENDPOINT`` setting.

Default: ``<OIDC_RP_PROVIDER_ENDPOINT>/authorize``

``OIDC_RP_PROVIDER_TOKEN_ENDPOINT``
-----------------------------------

This setting defines the token endpoint URL of the OIDC provider. Unless explicitely defined, it is
automatically generated from the ``OIDC_RP_PROVIDER_ENDPOINT`` setting.

Default: ``<OIDC_RP_PROVIDER_ENDPOINT>/token``

``OIDC_RP_PROVIDER_JWKS_ENDPOINT``
----------------------------------

This setting defines the JWKs endpoint URL of the OIDC provider. This endpoint can be provided by
the OIDC provider to expose its JWK Set. Unless explicitely defined, it is automatically generated
from the ``OIDC_RP_PROVIDER_ENDPOINT`` setting.

Default: ``<OIDC_RP_PROVIDER_ENDPOINT>/jwks``

``OIDC_RP_PROVIDER_USERINFO_ENDPOINT``
--------------------------------------

This setting defines the userinfo endpoint URL of the OIDC provider. This endpoint allows relying
parties to retrieve user information according to the scopes they've been granted. Unless
explicitely defined, it is automatically generated from the ``OIDC_RP_PROVIDER_ENDPOINT`` setting.

Default: ``<OIDC_RP_PROVIDER_ENDPOINT>/userinfo``

``OIDC_RP_PROVIDER_END_SESSION_ENDPOINT``
-----------------------------------------

This setting defines the end session endpoint URL of the OIDC provider. OIDC providers are not
required to implement this endpoint. It should be manually set in your Django settings.

Default: ``None``

.. note::

    The end-session endpoint is usefull it is necessary to ensure that a logout initiated from the
    relying partu also ends the session at the OIDC provider level. This process is explained in
    details in the
    `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
    specification.

``OIDC_RP_PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER``
-------------------------------------------------------

This setting defines which URI should be passed to the end-session endpoint of the OpenID Connect
provider in order to redirect the end-user back to the client application after a logout. This
setting is only used if the ``OIDC_RP_PROVIDER_END_SESSION_ENDPOINT`` setting is set.

Default: ``post_logout_redirect_uri``

``OIDC_RP_PROVIDER_END_SESSION_ID_TOKEN_PARAMETER``
---------------------------------------------------

This setting defines the name of the GET parameter used to pass the ID token to the provider's
end-session endpoint as a hint about the end-user's current session with the client.This setting is
only used if the ``OIDC_RP_PROVIDER_END_SESSION_ENDPOINT`` setting is set.

Default: ``id_token_hint``

``OIDC_RP_PROVIDER_SIGNATURE_ALG``
----------------------------------

This setting defines the signature algorithm used by the OpenID Connect Provider to sign ID tokens.
The value of this setting should be ``HS256`` or ``RS256``.

Default: ``HS256``

``OIDC_RP_PROVIDER_SIGNATURE_KEY``
----------------------------------

This setting defines the value of the key used by the OP to the sign ID tokens. It should be used
only when the ``OIDC_RP_PROVIDER_SIGNATURE_ALG`` setting is set to ``RS256``.

Default: ``None``

``OIDC_RP_USE_STATE``
---------------------

This setting defines whether or not states should be used when forging authorization requests.
States are used to maintain state between the authentication request and the callback.

Default: ``True``

``OIDC_RP_STATE_LENGTH``
------------------------

This setting defines the length of the opaque value used to maintain state between the
authentication request and the callback. It is used to mitigate Cross-Site Request Forgery
(CSRF, XSRF) by cryptographically binding the value with a cookie / a session key.

Default: ``32``

``OIDC_RP_SCOPES``
------------------

This setting defines the OpenID Connect scopes to request during authentication.

Default: ``openid email``

``OIDC_RP_USE_NONCE``
---------------------

This setting defines whether or not nonces should be used when forging authorization requests.
Nonces are used to mitigate replay attacks.

Default: ``True``

``OIDC_RP_NONCE_LENGTH``
------------------------

This setting defines the length of the nonce used to mitigate replay attacks when forging
authorization requests.

Default: ``32``

``OIDC_RP_ID_TOKEN_MAX_AGE``
----------------------------

This setting defines the amount of time (in seconds) an ``id_token`` should be considered valid.

Default: ``600``

``OIDC_RP_ID_TOKEN_INCLUDE_USERINFO``
-------------------------------------

This settings defines whether the ``id_token`` content can be used to retrieve userinfo claims and
scopes in order to create and update the user being authenticated.

Default: ``False``

``OIDC_RP_AUTHENTICATION_REDIRECT_URI``
---------------------------------------

This setting defines the URI that should be used to redirect the end-user after a successful
authentication performed by the OIDC provider if the callback gets no "next" parameter.

Default: ``/``

``OIDC_RP_AUTHENTICATION_FAILURE_REDIRECT_URI``
-----------------------------------------------

This setting defines the URI that should be used to redirect the end-user after a failed
authentication.

Default: ``/``

``OIDC_RP_USER_DETAILS_HANDLER``
--------------------------------

This setting defines a Python path towards a function that should be executed each time users sign
in (or sign up) to the application using OpenID Connect. The considered function takes the OpenID
Connect user instance and the claims dictionary as main arguments. It should be responsible for
creating whatever is necessary to manage the user later on.

Default: ``None``

``OIDC_RP_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY``
--------------------------------------------------

This settings defines a fixed string to use as a browser-state key for unauthenticated clients. It
can be usefull to define this value when it comes to supporting the
`OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
specification. Authenticated users are associated with a session state which is generated by the
OpenID Connect Provider but this is not the case for anonymous users. This is why this key should be
defined on the OP level and on relying parties when applicable. The ``session_state`` value for
anonymous users will be computed by using this key.

Default: ``None``
