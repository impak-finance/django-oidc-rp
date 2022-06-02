import datetime as dt
import json
import os
from calendar import timegm

import httpretty
import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from jwkest.jwk import KEYS, RSAKey
from jwkest.jws import JWS
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from oidc_rp.conf import settings as oidc_rp_settings
from oidc_rp.contrib.rest_framework.authentication import BearerTokenAuthentication
from oidc_rp.models import OIDCUser
from oidc_rp.signals import oidc_user_created


FIXTURE_ROOT = os.path.join(os.path.dirname(__file__), 'fixtures')


@pytest.mark.django_db
class TestBearerTokenAuthentication:
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

    def test_can_authenticate_a_new_user(self):
        rf = APIRequestFactory()
        request = rf.get('/', HTTP_AUTHORIZATION='Bearer accesstoken')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        user, _ = backend.authenticate(request)
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'

    def test_can_authenticate_an_existing_user(self):
        rf = APIRequestFactory()
        request = rf.get('/', HTTP_AUTHORIZATION='Bearer accesstoken')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        user = get_user_model().objects.create_user('test', 'test@example.com')
        OIDCUser.objects.create(user=user, sub='1234')
        user, _ = backend.authenticate(request)
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'

    def test_cannot_authenticate_a_user_if_no_auth_header_is_present(self):
        rf = APIRequestFactory()
        request = rf.get('/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        assert backend.authenticate(request) is None

    def test_cannot_authenticate_a_user_if_the_auth_header_is_not_a_bearer_authentication(self):
        rf = APIRequestFactory()
        request = rf.get('/', HTTP_AUTHORIZATION='DummyAuth accesstoken')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        assert backend.authenticate(request) is None

    def test_cannot_authenticate_a_user_if_the_auth_header_does_not_contain_the_access_token(self):
        rf = APIRequestFactory()
        request = rf.get('/', HTTP_AUTHORIZATION='Bearer')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        with pytest.raises(AuthenticationFailed):
            backend.authenticate(request)

    def test_cannot_authenticate_a_user_if_multiple_tokens_are_present_in_the_auth_header(self):
        rf = APIRequestFactory()
        request = rf.get('/', HTTP_AUTHORIZATION='Bearer token1 token2')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        with pytest.raises(AuthenticationFailed):
            backend.authenticate(request)

    def test_cannot_authenticate_a_user_if_the_userinfo_endpoint_raises_an_error(self):
        httpretty.register_uri(
            httpretty.GET, oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
            body='Nop', status=401)
        rf = APIRequestFactory()
        request = rf.get('/', HTTP_AUTHORIZATION='Bearer badtoken')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        with pytest.raises(AuthenticationFailed):
            backend.authenticate(request)

    def test_oidc_user_created_signal_is_sent_during_new_user_authentication(self, rf):
        self.signal_was_called = False

        def handler(sender, request, oidc_user, **kwargs):
            self.request = request
            self.oidc_user = oidc_user
            self.signal_was_called = True

        oidc_user_created.connect(handler)

        request = rf.get('/', HTTP_AUTHORIZATION='Bearer accesstoken')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = BearerTokenAuthentication()
        user, _ = backend.authenticate(request)

        assert self.signal_was_called is True
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'

        oidc_user_created.disconnect(handler)
