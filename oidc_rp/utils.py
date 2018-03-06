"""
    OpenID Connect relying party (RP) utilities
    ===========================================

    This modules defines utilities allowing to manipulate ID tokens and other common helpers.

"""

import datetime as dt
from calendar import timegm
from urllib.parse import urlparse

from django.core.exceptions import SuspiciousOperation
from django.utils.encoding import force_bytes, smart_bytes
from jwkest import JWKESTException
from jwkest.jwk import KEYS
from jwkest.jws import JWS

from .conf import settings as oidc_rp_settings


def validate_and_return_id_token(jws, nonce=None, validate_nonce=True):
    """ Validates the id_token according to the OpenID Connect specification. """
    shared_key = oidc_rp_settings.CLIENT_SECRET \
        if oidc_rp_settings.PROVIDER_SIGNATURE_ALG == 'HS256' \
        else oidc_rp_settings.PROVIDER_SIGNATURE_KEY  # RS256

    try:
        # Decodes the JSON Web Token and raise an error if the signature is invalid.
        id_token = JWS().verify_compact(force_bytes(jws), _get_jwks_keys(shared_key))
    except JWKESTException:
        return

    # Validates the claims embedded in the id_token.
    _validate_claims(id_token, nonce=nonce, validate_nonce=validate_nonce)

    return id_token


def _get_jwks_keys(shared_key):
    """ Returns JWKS keys used to decrypt id_token values. """
    # The OpenID Connect Provider (OP) uses RSA keys to sign/enrypt ID tokens and generate public
    # keys allowing to decrypt them. These public keys are exposed through the 'jwks_uri' and should
    # be used to decrypt the JWS - JSON Web Signature.
    jwks_keys = KEYS()
    jwks_keys.load_from_url(oidc_rp_settings.PROVIDER_JWKS_ENDPOINT)
    # Adds the shared key (which can correspond to the client_secret) as an oct key so it can be
    # used for HMAC signatures.
    jwks_keys.add({'key': smart_bytes(shared_key), 'kty': 'oct'})
    return jwks_keys


def _validate_claims(id_token, nonce=None, validate_nonce=True):
    """ Validates the claims embedded in the JSON Web Token. """
    iss_parsed_url = urlparse(id_token['iss'])
    provider_parsed_url = urlparse(oidc_rp_settings.PROVIDER_ENDPOINT)
    if iss_parsed_url.netloc != provider_parsed_url.netloc:
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

    # Verifies that the token was issued in the allowed timeframe.
    if utc_timestamp > id_token['iat'] + oidc_rp_settings.ID_TOKEN_MAX_AGE:
        raise SuspiciousOperation('Incorrect id_token: iat')

    # Validate the nonce to ensure the request was not modified if applicable.
    id_token_nonce = id_token.get('nonce', None)
    if validate_nonce and oidc_rp_settings.USE_NONCE and id_token_nonce != nonce:
        raise SuspiciousOperation('Incorrect id_token: nonce')
