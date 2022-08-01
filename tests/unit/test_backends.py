import datetime as dt
import json
import os
import unittest.mock
from calendar import timegm

import httpretty
import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import SuspiciousOperation, ImproperlyConfigured
from django.core.handlers.wsgi import WSGIRequest
from django.urls import resolve
from jwkest.jwk import KEYS, RSAKey
from jwkest.jws import JWS

from oidc_rp.backends import OIDCAuthBackend
from oidc_rp.conf import settings as oidc_rp_settings
from oidc_rp.models import OIDCUser
from oidc_rp.signals import oidc_user_created


FIXTURE_ROOT = os.path.join(os.path.dirname(__file__), 'fixtures')


def set_users_as_staff_members(oidc_user, claims):
    oidc_user.user.is_staff = True
    oidc_user.user.save()


@pytest.mark.django_db
class TestOIDCAuthBackend:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.old_response_type = oidc_rp_settings.RESPONSE_TYPE
        oidc_rp_settings.RESPONSE_TYPE = "code"

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

    def teardown(self):
        oidc_rp_settings.RESPONSE_TYPE = self.old_response_type

    def generate_jws(self, **kwargs):
        return JWS(self.generate_jws_dict(**kwargs), jwk=self.key, alg='RS256').sign_compact()

    def generate_jws_dict(self, **kwargs):
        client_key = kwargs.get('client_key', oidc_rp_settings.CLIENT_ID)
        now_dt = dt.datetime.utcnow()
        expiration_dt = kwargs.get('expiration_dt', (now_dt + dt.timedelta(seconds=30)))
        issue_dt = kwargs.get('issue_dt', now_dt)
        nonce = kwargs.get('nonce', 'nonce')
        ret = kwargs
        ret.update({
            'iss': kwargs.get('iss', oidc_rp_settings.PROVIDER_ENDPOINT),
            'nonce': nonce,
            'aud': kwargs.get('aud', client_key),
            'azp': kwargs.get('azp', client_key),
            'exp': timegm(expiration_dt.utctimetuple()),
            'iat': timegm(issue_dt.utctimetuple()),
            'nbf': timegm(kwargs.get('nbf', now_dt).utctimetuple()),
            'sub': '1234',
        })
        return ret

    def test_can_authenticate_a_new_user(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.oidc_users.first().iss == oidc_rp_settings.PROVIDER_ENDPOINT

    def test_can_authenticate_an_existing_user(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = get_user_model().objects.create_user('test', 'test@example.com')
        OIDCUser.objects.create(user=user, sub='1234')
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.oidc_users.first().iss == oidc_rp_settings.PROVIDER_ENDPOINT

    def test_can_authenticate_an_existing_user_with_provider(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = get_user_model().objects.create_user('test', 'test@example.com')
        OIDCUser.objects.create(user=user, sub='1234', iss=oidc_rp_settings.PROVIDER_ENDPOINT)
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.oidc_users.first().iss == oidc_rp_settings.PROVIDER_ENDPOINT
        assert False

    def test_can_authenticate_an_existing_user_with_different_provider(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = get_user_model().objects.create_user('test', 'test@example.com')
        OIDCUser.objects.create(user=user, sub='12556', iss="http://other-provider.example.com/")
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 2
        assert user.oidc_users.last().sub == '1234'
        assert user.oidc_users.last().iss == oidc_rp_settings.PROVIDER_ENDPOINT

    def test_can_handle_duplicate_subs_from_different_providers(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = get_user_model().objects.create_user('conflict', 'conflict@example.com')
        OIDCUser.objects.create(user=user, sub='1234', iss="http://other-provider.example.com/")
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.oidc_users.first().iss == oidc_rp_settings.PROVIDER_ENDPOINT
        assert OIDCUser.objects.count() == 2  # the conflicting user still exists

    def test_can_authenticate_a_new_user_even_if_no_email_is_in_userinfo_data(self, rf):
        httpretty.register_uri(
            httpretty.GET, oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
            body=json.dumps({'sub': '1234', }),
            content_type='text/json',
        )
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate(request, 'nonce')
        assert not user.email
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'

    def test_can_authenticate_a_user_with_token_flow(self, rf):
        oidc_rp_settings.RESPONSE_TYPE = "token"
        request = rf.post(
            '/oidc/cb/', {'state': 'state', 'access_token': 'accesstoken'}, content_type='application/json'
        )
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.oidc_users.first().iss == oidc_rp_settings.PROVIDER_ENDPOINT

    def test_can_authenticate_a_user_with_oidc_implicit_flow(self, rf):
        oidc_rp_settings.RESPONSE_TYPE = "id_token token"
        id_token = self.generate_jws(at_hash="IWbUdP6sROHIAd085N_3jg")
        request = rf.post(
            '/oidc/cb/',
            {'state': 'state', 'access_token': 'accesstoken', 'id_token': id_token},
            content_type='application/json'
        )
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.oidc_users.first().iss == oidc_rp_settings.PROVIDER_ENDPOINT

    def test_cannot_authenticate_a_user_if_the_nonce_is_not_provided_and_if_it_is_mandatory(
            self, rf):
        request = rf.get('/oidc/cb/', {'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        assert backend.authenticate(None, request) is None

    def test_cannot_authenticate_a_user_if_the_request_object_is_not_provided(self, rf):
        request = rf.get('/oidc/cb/', {'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        assert backend.authenticate('nonce', None) is None

    def test_cannot_authenticate_a_user_if_the_state_is_not_present_in_the_request_parameters(
            self, rf):
        request = rf.get('/oidc/cb/', {'code': 'authcode', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        with pytest.raises(SuspiciousOperation):
            backend.authenticate(request, 'nonce')

    def test_cannot_authenticate_a_user_if_the_code_is_not_present_in_the_request_parameters(
            self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', })
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        with pytest.raises(SuspiciousOperation):
            backend.authenticate(request, 'nonce')

    def test_cannot_authenticate_a_user_if_the_id_token_validation_shows_a_suspicious_operation(
            self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        with pytest.raises(SuspiciousOperation):
            backend.authenticate(request, 'badnonce')

    def test_cannot_authenticate_a_user_if_the_id_token_validation_fails(self, rf):
        httpretty.register_uri(
            httpretty.POST, oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT,
            body=json.dumps({
                'id_token': 'badidtoken', 'access_token': 'accesstoken',
                'refresh_token': 'refreshtoken', }),
            content_type='text/json')
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        assert backend.authenticate(request, 'nonce') is None

    def test_cannot_authenticate_a_user_in_implicit_flow_if_the_id_token_validation_fails(self, rf):
        oidc_rp_settings.RESPONSE_TYPE = "id_token token"
        request = rf.post(
            '/oidc/cb/',
            {'state': 'state', 'access_token': 'accesstoken', 'id_token': 'badidtoken'},
            content_type='application/json'
        )
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        assert backend.authenticate(request, 'nonce') is None

    def test_cannot_authenticate_a_user_with_unsupported_response_type(self, rf):
        oidc_rp_settings.RESPONSE_TYPE = "incorrect"
        request = rf.get('/oidc/cb/', {})
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        with pytest.raises(ImproperlyConfigured):
            backend.authenticate(request, 'nonce')

    @unittest.mock.patch('oidc_rp.conf.settings.USER_DETAILS_HANDLER',
                         'tests.unit.test_backends.set_users_as_staff_members')
    def test_can_authenticate_a_new_user_and_update_its_details_with_a_specific_handler(self, rf):
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'
        assert user.is_staff

    @unittest.mock.patch('oidc_rp.conf.settings.ID_TOKEN_INCLUDE_USERINFO', True)
    def test_can_process_userinfo_included_in_the_id_token_instead_of_calling_the_userinfo_endpoint(
            self, rf):
        httpretty.register_uri(
            httpretty.POST, oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT,
            body=json.dumps({
                'id_token': self.generate_jws(email='test1@example.com'),
                'access_token': 'accesstoken',
                'refresh_token': 'refreshtoken',
            }),
            content_type='text/json')
        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        user = backend.authenticate(request, 'nonce')
        assert user.email == 'test1@example.com'
        assert user.oidc_users.count() == 1
        assert user.oidc_users.first().sub == '1234'

    def test_oidc_user_created_signal_is_sent_during_new_user_authentication(self, rf):
        self.signal_was_called = False

        def handler(sender, request, oidc_user, **kwargs):
            self.request = request
            self.oidc_user = oidc_user
            self.signal_was_called = True

        oidc_user_created.connect(handler)

        request = rf.get('/oidc/cb/', {'state': 'state', 'code': 'authcode', })
        request.resolver_match = resolve('/oidc/auth/cb/')
        SessionMiddleware().process_request(request)
        request.session.save()
        backend = OIDCAuthBackend()
        backend.authenticate(request, 'nonce')

        assert self.signal_was_called is True
        assert type(self.request) is WSGIRequest
        assert self.oidc_user.userinfo['email'] == 'test@example.com'
        assert self.oidc_user.userinfo['sub'] == '1234'

        oidc_user_created.disconnect(handler)
