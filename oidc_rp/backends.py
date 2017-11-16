"""
    OpenID Connect authentication backends
    ======================================

    This modules defines backends allowing to authenticate a user using a specific token endpoint
    of an OpenID Connect provider (OP).

"""

import base64
import datetime as dt
import hashlib
from calendar import timegm

import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse
from django.utils.encoding import force_bytes, smart_bytes, smart_text
from jwkest import JWKESTException
from jwkest.jwk import KEYS
from jwkest.jws import JWS

from .conf import settings as oidc_rp_settings


class OIDCAuthBackend(ModelBackend):
    """ Allows to authenticate users using an OpenID Connect Provider (OP).

    This authentication backend is able to authenticate users in the case of the OpenID Connect
    Authorization Code flow. The ``authenticate`` method provided by this backend is likely to be
    called when the callback URL is requested by the OpenID Connect Provider (OP). Thus it will
    call the OIDC provider again in order to request a valid token using the authorization code that
    should be available in the request parameters associated with the callback call.

    """

    def authenticate(self, nonce, request):
        """ Authenticates users in case of the OpenID Connect Authorization code flow. """
        # NOTE: the request object is mandatory to perform the authentication using an authorization
        # code provided by the OIDC supplier.
        if nonce is None or request is None:
            return

        # Fetches required GET parameters from the HTTP request object.
        state = request.GET.get('state')
        code = request.GET.get('code')

        # Don't go further if the state value or the authorization code is not present in the GET
        # parameters because we won't be able to get a valid token for the user in that case.
        if state is None or code is None:
            raise SuspiciousOperation('Authorization code or state value is missing')

        # Prepares the token payload that will be used to request an authentication token to the
        # token endpoint of the OIDC provider.
        token_payload = {
            'client_id': oidc_rp_settings.CLIENT_ID,
            'client_secret': oidc_rp_settings.CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': request.build_absolute_uri(reverse('oidc_auth_callback')),
        }

        # Calls the token endpoint.
        token_response = requests.post(oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT, data=token_payload)
        token_response.raise_for_status()
        token_response_data = token_response.json()

        # Validates the token.
        id_token = self.validate_and_return_id_token(token_response_data.get('id_token'), nonce)
        if id_token is None:
            return

        # Retrieves the access token.
        access_token = token_response_data.get('access_token')

        # Fetches the user information from the userinfo endpoint provided by the OP.
        userinfo_response = requests.get(
            oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
            headers={'Authorization': 'Bearer {0}'.format(access_token)})
        userinfo_response.raise_for_status()
        userinfo_response_data = userinfo_response.json()

        # Tries to retrieve a corresponding user in the local database and creates it if applicable.
        users = list(filter_users_from_claims(userinfo_response_data))
        print(users, userinfo_response_data)

        if len(users) == 1:
            return users[0]
        elif len(users) > 1:
            # In the case where two users with the same identifier were found we cannot choose which
            # one to authenticate.
            return None
        else:
            # Otherwise we create a local user for our authenticated user.
            return create_user_from_claims(userinfo_response_data)

    def get_jwks_keys(self, shared_key):
        """ Returns JWKS keys used to decrypt id_token values. """
        # The OpenID Connect Provider (OP) uses RSA keys to sign/enrypt ID tokens and generate
        # public keys allowing to decrypt them. These public keys are exposed through the 'jwks_uri'
        # and should be used to decrypt the JWS - JSON Web Signature.
        jwks_keys = KEYS()
        jwks_keys.load_from_url(oidc_rp_settings.PROVIDER_JWKS_ENDPOINT)
        # Adds the shared key (which can correspond to the client_secret) as an oct key so it can be
        # used for HMAC signatures.
        jwks_keys.add({'key': smart_bytes(shared_key), 'kty': 'oct'})
        return jwks_keys

    def validate_and_return_id_token(self, jws, nonce=None):
        """ Validates the id_token according to the OpenID Connect specification. """
        # TODO: add support for RS256.
        shared_key = oidc_rp_settings.CLIENT_SECRET

        try:
            # Decodes the JSON Web Token and raise an error if the signature is invalid.
            id_token = JWS().verify_compact(force_bytes(jws), self.get_jwks_keys(shared_key))
        except JWKESTException:
            return

        # Validates the claims embedded in the id_token.
        self.validate_claims(id_token, nonce=nonce)

        return id_token

    def validate_claims(self, id_token, nonce=None):
        """ Validates the claims embedded in the JSON Web Token. """
        if id_token['iss'].rstrip('/') != oidc_rp_settings.PROVIDER_ENDPOINT.rstrip('/'):
            raise SuspiciousOperation('Invalid issuer')

        if isinstance(id_token['aud'], str):
            id_token['aud'] = [id_token['aud']]

        if oidc_rp_settings.CLIENT_ID not in id_token['aud']:
            raise SuspiciousOperation('Invalid audience')

        if len(id_token['aud']) > 1 and 'azp' not in id_token:
            raise SuspiciousOperation('Incorrect id_token: azp')

        if 'azp' in id_token and id_token['azp'] != oidc_rp_settings.CLIENT_ID:
            raise SuspiciousOperation('Incorrect id_token: azp')

        utc_timestamp = timegm(dt.datetime.utcnow().utctimetuple())
        if utc_timestamp > id_token['exp']:
            raise SuspiciousOperation('Signature has expired')

        if 'nbf' in id_token and utc_timestamp < id_token['nbf']:
            raise SuspiciousOperation('Incorrect id_token: nbf')

        # Verifies that the token was issued in the last 10 minutes.
        # TODO: add a setting for the ID_TOKEN_MAX_AGE value???
        if utc_timestamp > id_token['iat'] + 600:
            raise SuspiciousOperation('Incorrect id_token: iat')

        # Validate the nonce to ensure the request was not modified if applicable.
        id_token_nonce = id_token.get('nonce', None)
        if oidc_rp_settings.USE_NONCE and id_token_nonce != nonce:
            raise SuspiciousOperation('Incorrect id_token: nonce')


def filter_users_from_claims(claims):
    """ Returns a queryset of users given a dictionary of claims extracted from an id_token. """
    return get_user_model().objects.filter(email__iexact=claims.get('email'))


def create_user_from_claims(claims):
    """ Creates a user using the claims extracted from an id_token. """
    email = claims.get('email')
    if not email:
        return None
    username = base64.urlsafe_b64encode(hashlib.sha1(force_bytes(email)).digest()).rstrip(b'=')
    return get_user_model().objects.create_user(smart_text(username), email)
