"""
    OpenID Connect relying party (RP) views
    =======================================

    This modules defines views allowing to start the authorization and authentication process in
    order to authenticate a specific user. The most important views are: the "login" allowing to
    authenticate the users using the OP and get an authorizartion code, the callback view allowing
    to retrieve a valid token for the considered user and the logout view.

"""

import time

from django.conf import settings
from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect, QueryDict
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import is_safe_url, urlencode
from django.views.generic import View

from .conf import settings as oidc_rp_settings


class OIDCAuthRequestView(View):
    """ Allows to start the authorization flow in order to authenticate the end-user.

    This view acts as the main endpoint to trigger the authentication process involving the OIDC
    provider (OP). It prepares an authentication request that will be sent to the authorization
    server in order to authenticate the end-user.

    """

    http_method_names = ['get', ]

    def get(self, request):
        """ Processes GET requests. """
        # Defines common parameters used to bootstrap the authentication request.
        authentication_request_params = request.GET.dict()
        authentication_request_params.update({
            'scope': oidc_rp_settings.SCOPES,
            'response_type': 'code',
            'client_id': oidc_rp_settings.CLIENT_ID,
            'redirect_uri': request.build_absolute_uri(reverse('oidc_auth_callback')),
        })

        # States should be used! They are recommended in order to maintain state between the
        # authentication request and the callback.
        if oidc_rp_settings.USE_STATE:
            state = get_random_string(oidc_rp_settings.STATE_LENGTH)
            authentication_request_params.update({'state': state})
            request.session['oidc_auth_state'] = state

        # Nonces should be used too! In that case the generated nonce is stored both in the
        # authentication request parameters and in the user's session.
        if oidc_rp_settings.USE_NONCE:
            nonce = get_random_string(oidc_rp_settings.NONCE_LENGTH)
            authentication_request_params.update({'nonce': nonce, })
            request.session['oidc_auth_nonce'] = nonce

        # Stores the "next" URL in the session if applicable.
        next_url = request.GET.get('next')
        request.session['oidc_auth_next_url'] = next_url \
            if is_safe_url(url=next_url, allowed_hosts=(request.get_host(), )) else None

        # Redirects the user to authorization endpoint.
        query = urlencode(authentication_request_params)
        redirect_url = '{url}?{query}'.format(
            url=oidc_rp_settings.PROVIDER_AUTHORIZATION_ENDPOINT, query=query)
        return HttpResponseRedirect(redirect_url)


class OIDCAuthCallbackView(View):
    """ Allows to complete the authentication process.

    This view acts as the main endpoint to complete the authentication process involving the OIDC
    provider (OP). It checks the request sent by the OIDC provider in order to determine whether the
    considered was successfully authentified or not and authenticates the user at the current
    application level if applicable.

    """

    http_method_names = ['get', ]

    def get(self, request):
        """ Processes GET requests. """
        callback_params = request.GET

        # Retrieve the state value that was previously generated. No state means that we cannot
        # authenticate the user (so a failure should be returned).
        state = request.session.get('oidc_auth_state', None)

        # Retrieve the nonce that was previously generated and remove it from the current session.
        # If no nonce is available (while the USE_NONCE setting is set to True) this means that the
        # authentication cannot be performed and so we have redirect the user to a failure URL.
        nonce = request.session.pop('oidc_auth_nonce', None)

        # NOTE: a redirect to the failure page should be return if some required GET parameters are
        # missing or if no state can be retrieved from the current session.

        if (
            ((nonce and oidc_rp_settings.USE_NONCE) or not oidc_rp_settings.USE_NONCE) and
            ((state and oidc_rp_settings.USE_STATE) or not oidc_rp_settings.USE_STATE) and
            ('code' in callback_params and 'state' in callback_params)
        ):
            # Ensures that the passed state values is the same as the one that was previously
            # generated when forging the authorization request. This is necessary to mitigate
            # Cross-Site Request Forgery (CSRF, XSRF).
            if oidc_rp_settings.USE_STATE and callback_params['state'] != state:
                raise SuspiciousOperation('Invalid OpenID Connect callback state value')

            # Authenticates the end-user.
            next_url = request.session.get('oidc_auth_next_url', None)
            user = auth.authenticate(nonce=nonce, request=request)
            if user and user.is_active:
                auth.login(self.request, user)
                # Stores an expiration timestamp in the user's session. This value will be used if
                # the project is configured to periodically refresh user's token.
                self.request.session['oidc_auth_id_token_exp_timestamp'] = \
                    time.time() + oidc_rp_settings.ID_TOKEN_MAX_AGE
                # Stores the "session_state" value that can be passed by the OpenID Connect provider
                # in order to maintain a consistent session state across the OP and the related
                # relying parties (RP).
                self.request.session['oidc_auth_session_state'] = \
                    callback_params.get('session_state', None)

                return HttpResponseRedirect(
                    next_url or oidc_rp_settings.AUTHENTICATION_REDIRECT_URI)

        if 'error' in callback_params:
            # If we receive an error in the callback GET parameters, this means that the
            # authentication could not be performed at the OP level. In that case we have to logout
            # the current user because we could've obtained this error after a prompt=none hit on
            # OpenID Connect Provider authenticate endpoint.
            auth.logout(request)

        return HttpResponseRedirect(oidc_rp_settings.AUTHENTICATION_FAILURE_REDIRECT_URI)


class OIDCEndSessionView(View):
    """ Allows to end the session of any user authenticated using OpenID Connect.

    This view acts as the main endpoint to end the session of an end-user that was authenticated
    using the OIDC provider (OP). It calls the "end-session" endpoint provided by the provider if
    applicable.

    """

    http_method_names = ['get', 'post', ]

    def get(self, request):
        """ Processes GET requests. """
        return self.post(request)

    def post(self, request):
        """ Processes POST requests. """
        logout_url = settings.LOGOUT_REDIRECT_URL or '/'

        # Log out the current user.
        if request.user.is_authenticated:
            try:
                logout_url = self.provider_end_session_url \
                    if oidc_rp_settings.PROVIDER_END_SESSION_ENDPOINT else logout_url
            except KeyError:  # pragma: no cover
                logout_url = logout_url
            auth.logout(request)

        # Redirects the user to the appropriate URL.
        return HttpResponseRedirect(logout_url)

    @property
    def provider_end_session_url(self):
        """ Returns the end-session URL. """
        q = QueryDict(mutable=True)
        q[oidc_rp_settings.PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER] = \
            self.request.build_absolute_uri(settings.LOGOUT_REDIRECT_URL or '/')
        q[oidc_rp_settings.PROVIDER_END_SESSION_ID_TOKEN_PARAMETER] = \
            self.request.session['oidc_auth_id_token']
        return '{}?{}'.format(oidc_rp_settings.PROVIDER_END_SESSION_ENDPOINT, q.urlencode())
