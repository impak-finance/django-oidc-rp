"""
    OpenID Connect relying party (RP) authentication backends
    =========================================================

    This modules defines backends allowing to authenticate a user using a specific token endpoint
    of an OpenID Connect provider (OP).

"""

import base64
import hashlib

import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.urls import reverse
from django.utils.encoding import force_bytes, smart_text
from django.utils.module_loading import import_string

from .conf import settings as oidc_rp_settings
from .models import OIDCUser
from .signals import oidc_user_created
from .utils import validate_and_return_id_token


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
        if (nonce is None and oidc_rp_settings.USE_NONCE) or request is None:
            return

        # Fetches required GET parameters from the HTTP request object.
        state = request.GET.get('state')
        code = request.GET.get('code')

        # Don't go further if the state value or the authorization code is not present in the GET
        # parameters because we won't be able to get a valid token for the user in that case.
        if (state is None and oidc_rp_settings.USE_STATE) or code is None:
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
        raw_id_token = token_response_data.get('id_token')
        id_token = validate_and_return_id_token(raw_id_token, nonce)
        if id_token is None:
            return

        # Retrieves the access token and refresh token.
        access_token = token_response_data.get('access_token')
        refresh_token = token_response_data.get('refresh_token')

        # Stores the ID token, the related access token and the refresh token in the session.
        request.session['oidc_auth_id_token'] = raw_id_token
        request.session['oidc_auth_access_token'] = access_token
        request.session['oidc_auth_refresh_token'] = refresh_token

        # If the id_token contains userinfo scopes and claims we don't have to hit the userinfo
        # endpoint.
        if oidc_rp_settings.ID_TOKEN_INCLUDE_USERINFO:
            print(id_token)
            userinfo_data = id_token
        else:
            # Fetches the user information from the userinfo endpoint provided by the OP.
            userinfo_response = requests.get(
                oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
                headers={'Authorization': 'Bearer {0}'.format(access_token)})
            userinfo_response.raise_for_status()
            userinfo_data = userinfo_response.json()

        # Tries to retrieve a corresponding user in the local database and creates it if applicable.
        try:
            oidc_user = OIDCUser.objects.select_related('user').get(sub=userinfo_data.get('sub'))
        except OIDCUser.DoesNotExist:
            oidc_user = create_oidc_user_from_claims(userinfo_data)
            oidc_user_created.send(sender=self.__class__, request=request, oidc_user=oidc_user)
        else:
            update_oidc_user_from_claims(oidc_user, userinfo_data)

        # Runs a custom user details handler if applicable. Such handler could be responsible for
        # creating / updating whatever is necessary to manage the considered user (eg. a profile).
        user_details_handler = import_string(oidc_rp_settings.USER_DETAILS_HANDLER) \
            if oidc_rp_settings.USER_DETAILS_HANDLER is not None else None
        if user_details_handler is not None:
            user_details_handler(oidc_user, userinfo_data)

        return oidc_user.user


@transaction.atomic
def create_oidc_user_from_claims(claims):
    """ Creates an ``OIDCUser`` instance using the claims extracted from an id_token. """
    sub = claims['sub']
    email = claims.get('email')
    username = base64.urlsafe_b64encode(hashlib.sha1(force_bytes(sub)).digest()).rstrip(b'=')
    user = get_user_model().objects.create_user(smart_text(username), email=email)
    oidc_user = OIDCUser.objects.create(user=user, sub=sub, userinfo=claims)
    return oidc_user


@transaction.atomic
def update_oidc_user_from_claims(oidc_user, claims):
    """ Updates an ``OIDCUser`` instance using the claims extracted from an id_token. """
    oidc_user.userinfo = claims
    oidc_user.save()
    oidc_user.user.email = claims.get('email')
    oidc_user.user.save()
