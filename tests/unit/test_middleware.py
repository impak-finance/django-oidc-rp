import datetime as dt
import json
import os
from calendar import timegm

import httpretty
import pytest
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.utils import timezone as tz
from jwkest.jwk import KEYS, RSAKey
from jwkest.jws import JWS

from oidc_rp.backends import OIDCAuthBackend
from oidc_rp.conf import settings as oidc_rp_settings
from oidc_rp.middleware import OIDCRefreshIDTokenMiddleware


FIXTURE_ROOT = os.path.join(os.path.dirname(__file__), 'fixtures')


@pytest.mark.django_db
class TestOIDCRefreshIDTokenMiddleware:
    @pytest.fixture(autouse=True)
    def setup(self):
        httpretty.enable()

        self.key = RSAKey(kid='testkey').load(os.path.join(FIXTURE_ROOT, 'testkey.pem'))
        def jwks(_request, _uri, headers):  # noqa: E306
            ks = KEYS()
            ks.add(self.key.serialize())
            return 200, headers, ks.dump_jwks()
        httpretty.register_uri(
            httpretty.GET, oidc_rp_settings.PROVIDER_JWKS_ENDPOINT, status=200, body=jwks)
        httpretty.register_uri(
            httpretty.POST, oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT,
            body=json.dumps({
                'id_token': self.generate_jws(), 'access_token': 'accesstoken',
                'refresh_token': 'refreshtoken', }),
            content_type='text/json')
        httpretty.register_uri(
            httpretty.GET, oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
            body=json.dumps({'sub': '1234', 'email': 'test@example.com', }),
            content_type='text/json')

        yield

        httpretty.disable()

    def generate_jws(self, **kwargs):
        return JWS(self.generate_jws_dict(**kwargs), jwk=self.key, alg='RS256').sign_compact()

    def generate_jws_dict(self, **kwargs):
        client_key = kwargs.get('client_key', oidc_rp_settings.CLIENT_ID)
        now_dt = dt.datetime.utcnow()
        expiration_dt = kwargs.get('expiration_dt', (now_dt + dt.timedelta(seconds=30)))
        issue_dt = kwargs.get('issue_dt', now_dt)
        nonce = kwargs.get('nonce', 'nonce')
        return {
            'iss': kwargs.get('iss', oidc_rp_settings.PROVIDER_ENDPOINT),
            'nonce': nonce,
            'aud': kwargs.get('aud', client_key),
            'azp': kwargs.get('azp', client_key),
            'exp': timegm(expiration_dt.utctimetuple()),
            'iat': timegm(issue_dt.utctimetuple()),
            'nbf': timegm(kwargs.get('nbf', now_dt).utctimetuple()),
            'sub': '1234',
        }

    def test_can_refresh_the_access_token_of_a_previously_authenticated_user(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate('nonce', request)
        request.session['oidc_auth_id_token_exp_timestamp'] = \
            (tz.now() - dt.timedelta(minutes=1)).timestamp()
        request.session['oidc_auth_refresh_token'] = 'this_is_a_refresh_token'
        auth.login(request, user)
        request.user = user
        middleware = OIDCRefreshIDTokenMiddleware(lambda r: 'OK')
        middleware(request)
        assert request.session['oidc_auth_refresh_token'] == 'refreshtoken'

    def test_can_properly_handle_the_case_where_a_user_was_authenticated_using_the_model_backend(
            self, rf):
        request = rf.get('/')
        SessionMiddleware().process_request(request)
        request.session.save()
        user = get_user_model().objects.create_user('test', 'test@example.com', 'insecure')
        request.user = user
        auth.authenticate(username='test', password='insecure')
        auth.login(request, user)
        middleware = OIDCRefreshIDTokenMiddleware(lambda r: 'OK')
        middleware(request)
        assert request.user == user
        assert request.user.is_authenticated

    def test_do_nothing_if_the_access_token_is_still_valid(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate('nonce', request)
        request.session['oidc_auth_id_token_exp_timestamp'] = \
            (tz.now() + dt.timedelta(minutes=1)).timestamp()
        request.session['oidc_auth_refresh_token'] = 'this_is_a_refresh_token'
        auth.login(request, user)
        request.user = user
        middleware = OIDCRefreshIDTokenMiddleware(lambda r: 'OK')
        middleware(request)
        assert request.session['oidc_auth_refresh_token'] == 'this_is_a_refresh_token'

    def test_log_out_the_user_if_the_id_token_is_not_valid(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate('nonce', request)
        request.session['oidc_auth_id_token_exp_timestamp'] = \
            (tz.now() - dt.timedelta(minutes=1)).timestamp()
        request.session['oidc_auth_refresh_token'] = 'this_is_a_refresh_token'
        auth.login(request, user)
        request.user = user

        httpretty.register_uri(
            httpretty.POST, oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT,
            body=json.dumps({
                'id_token': 'badidtoken', 'access_token': 'accesstoken',
                'refresh_token': 'refreshtoken', }),
            content_type='text/json')

        middleware = OIDCRefreshIDTokenMiddleware(lambda r: 'OK')
        middleware(request)
        assert not request.user.is_authenticated

    def test_log_out_the_user_if_the_refresh_token_is_expired(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate('nonce', request)
        request.session['oidc_auth_id_token_exp_timestamp'] = \
            (tz.now() - dt.timedelta(minutes=1)).timestamp()
        request.session['oidc_auth_refresh_token'] = 'this_is_a_refresh_token'
        auth.login(request, user)
        request.user = user

        httpretty.register_uri(
            httpretty.POST, oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT,
            body=json.dumps({'error': 'yes'}),
            content_type='text/json', status=400)

        middleware = OIDCRefreshIDTokenMiddleware(lambda r: 'OK')
        middleware(request)
        assert not request.user.is_authenticated
