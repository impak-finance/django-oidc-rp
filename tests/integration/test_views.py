import unittest.mock
from urllib.parse import parse_qs, urlparse

import json
import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from django.urls import reverse

from oidc_rp.conf import settings as oidc_rp_settings
from pytest_django.asserts import assertTemplateUsed


@pytest.mark.django_db
class TestOIDCAuthRequestView:
    def test_can_redirect_the_user_to_the_authorization_server_to_be_authenticated(self, client):
        url = reverse('oidc_rp:oidc_auth_request')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        assert response.url.startswith('http://example.com/a/authorize')
        parsed_parameters = parse_qs(urlparse(response.url).query)
        assert parsed_parameters['response_type'] == ['code', ]
        assert parsed_parameters['scope'] == ['openid email', ]
        assert parsed_parameters['client_id'] == ['DUMMY_CLIENT_ID', ]
        assert parsed_parameters['redirect_uri'] == ['http://testserver/oidc/auth/cb/', ]
        assert parsed_parameters['state']
        assert parsed_parameters['nonce']

    @unittest.mock.patch('oidc_rp.conf.settings.USE_NONCE', False)
    def test_do_not_embed_a_nonce_in_the_request_parameters_if_the_related_setting_is_disabled(
            self, client):
        url = reverse('oidc_rp:oidc_auth_request')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        parsed_parameters = parse_qs(urlparse(response.url).query)
        assert parsed_parameters['response_type'] == ['code', ]
        assert parsed_parameters['scope'] == ['openid email', ]
        assert parsed_parameters['client_id'] == ['DUMMY_CLIENT_ID', ]
        assert parsed_parameters['redirect_uri'] == ['http://testserver/oidc/auth/cb/', ]
        assert parsed_parameters['state']
        assert 'nonce' not in parsed_parameters

    @unittest.mock.patch('oidc_rp.conf.settings.USE_STATE', False)
    def test_do_not_embed_a_state_in_the_request_parameters_if_the_related_setting_is_disabled(
            self, client):
        url = reverse('oidc_rp:oidc_auth_request')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        parsed_parameters = parse_qs(urlparse(response.url).query)
        assert parsed_parameters['response_type'] == ['code', ]
        assert parsed_parameters['scope'] == ['openid email', ]
        assert parsed_parameters['client_id'] == ['DUMMY_CLIENT_ID', ]
        assert parsed_parameters['redirect_uri'] == ['http://testserver/oidc/auth/cb/', ]
        assert 'state' not in parsed_parameters

    def test_saves_the_authorization_state_value_in_the_user_session(self, client):
        url = reverse('oidc_rp:oidc_auth_request')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        parsed_parameters = parse_qs(urlparse(response.url).query)
        assert client.session['oidc_auth_state'] == parsed_parameters['state'][0]

    def test_saves_the_nonce_value_in_the_user_session_if_applicable(self, client):
        url = reverse('oidc_rp:oidc_auth_request')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        parsed_parameters = parse_qs(urlparse(response.url).query)
        assert client.session['oidc_auth_nonce'] == parsed_parameters['nonce'][0]


@pytest.mark.django_db
class TestOIDCAuthCallbackView:
    def setup(self):
        self.old_response_type = oidc_rp_settings.RESPONSE_TYPE
        oidc_rp_settings.RESPONSE_TYPE = "code"

    def teardown(self):
        oidc_rp_settings.RESPONSE_TYPE = self.old_response_type

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    def test_can_properly_authenticate_users_and_redirect_them_to_a_success_url(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 302
        assert response.url == '/success'
        assert mocked_authenticate.call_count == 1
        assert mocked_login.call_count == 1

    @pytest.mark.parametrize('response_type', ("id_token token", "token"))
    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_implicit_callback_get_renders_parsing_template(self, mocked_authenticate, client, response_type):
        oidc_rp_settings.RESPONSE_TYPE = response_type
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {})
        assertTemplateUsed("implicit_login.html")
        assert response.context['success_redirect_url'] == '/success'
        assert response.context['failure_redirect_url'] == '/fail'

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    @pytest.mark.parametrize('response_type, post_data', (
        ("id_token token", {'access_token': 'dummyaccesstoken', 'id_token': 'dummyidtoken'}),
        ("token", {'access_token': 'dummyaccesstoken', })
    ))
    def test_implicit_callback_post_can_properly_authenticate_users_and_return_success(
            self, mocked_login, mocked_authenticate, client, response_type, post_data):
        oidc_rp_settings.RESPONSE_TYPE = response_type
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.post(url, {**post_data, 'state': 'dummystate'}, content_type='application/json')
        assert json.loads(response.content) == {'status': 'success', 'next_url': None}
        assert mocked_authenticate.call_count == 1
        assert mocked_login.call_count == 1

    @pytest.mark.parametrize('response_type', ("id_token token", "token"))
    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    def test_implicit_callback_post_returns_failure_on_missing_callback_params(
            self, mocked_login, mocked_authenticate, client, response_type):
        oidc_rp_settings.RESPONSE_TYPE = response_type
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.post(url, {'state': 'dummystate'}, content_type='application/json')
        assert json.loads(response.content) == {'status': 'failure'}
        assert mocked_authenticate.call_count == 0
        assert mocked_login.call_count == 0

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    @unittest.mock.patch('oidc_rp.conf.settings.USE_NONCE', False)
    def test_can_properly_authenticate_users_and_redirect_them_to_a_success_url_without_nonce(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 302
        assert response.url == '/success'
        assert mocked_authenticate.call_count == 1
        assert mocked_login.call_count == 1

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    def test_can_properly_authenticate_users_and_redirect_them_to_a_custom_success_url(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session['oidc_auth_next_url'] = '/profile'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 302
        assert response.url == '/profile'
        assert mocked_authenticate.call_count == 1
        assert mocked_login.call_count == 1

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_can_redirect_users_to_a_failure_page_in_case_of_missing_nonce(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 302
        assert response.url == '/fail'
        assert not mocked_authenticate.call_count
        assert not mocked_login.call_count

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_can_redirect_users_to_a_failure_page_in_case_of_missing_code_param_in_code_response(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'state': 'dummystate', 'access_token': 'dummyaccesstoken'})
        assert response.status_code == 302
        assert response.url == '/fail'
        assert not mocked_authenticate.call_count
        assert not mocked_login.call_count

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_can_redirect_users_to_a_failure_page_in_case_of_missing_state_parameter(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode'})
        assert response.status_code == 302
        assert response.url == '/fail'
        assert not mocked_authenticate.call_count
        assert not mocked_login.call_count

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_can_redirect_the_to_a_failure_page_if_he_is_not_active(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        user.is_active = False
        user.save()
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 302
        assert response.url == '/fail'
        assert mocked_authenticate.call_count == 1
        assert not mocked_login.call_count

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_raises_if_the_state_has_been_tampered_with(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'validstate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 400  # suspicious operation
        assert not mocked_authenticate.call_count
        assert not mocked_login.call_count

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_raises_if_the_response_type_is_not_supported(
            self, mocked_login, mocked_authenticate, client):
        oidc_rp_settings.RESPONSE_TYPE = "incorrect"
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')

        with pytest.raises(ImproperlyConfigured):
            client.get(url, {'state': 'dummystate', 'code': 'dummycode'})

        assert not mocked_authenticate.call_count
        assert not mocked_login.call_count

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    def test_removes_nonce_from_user_session_upon_user_authentication(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'code': 'dummycode', 'state': 'dummystate'})
        assert response.status_code == 302
        assert response.url == '/success'
        assert mocked_authenticate.call_count == 1
        assert mocked_login.call_count == 1
        assert 'oidc_auth_state' in client.session
        assert 'oidc_auth_nonce' not in client.session

    @unittest.mock.patch('django.contrib.auth.authenticate')
    @unittest.mock.patch('django.contrib.auth.login')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_REDIRECT_URI', '/success')
    def test_stores_the_session_state_if_applicable(
            self, mocked_login, mocked_authenticate, client):
        user = User.objects.create_user('foo')
        mocked_authenticate.return_value = user
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(
            url, {'code': 'dummycode', 'state': 'dummystate', 'session_state': 'thisisatest', })
        assert response.status_code == 302
        assert response.url == '/success'
        assert mocked_authenticate.call_count == 1
        assert mocked_login.call_count == 1
        assert client.session['oidc_auth_session_state'] == 'thisisatest'

    @unittest.mock.patch('django.contrib.auth.logout')
    @unittest.mock.patch('oidc_rp.conf.settings.AUTHENTICATION_FAILURE_REDIRECT_URI', '/fail')
    def test_logout_the_current_user_if_the_authentication_failed_on_the_op(
            self, mocked_logout, client):
        session = client.session
        session['oidc_auth_state'] = 'dummystate'
        session['oidc_auth_nonce'] = 'dummynonce'
        session.save()
        url = reverse('oidc_rp:oidc_auth_callback')
        response = client.get(url, {'error': 'login_required', })
        assert response.status_code == 302
        assert response.url == '/fail'
        assert mocked_logout.call_count == 1


@pytest.mark.django_db
class TestOIDCEndSessionView:
    @unittest.mock.patch('django.contrib.auth.logout')
    @unittest.mock.patch('oidc_rp.conf.settings.PROVIDER_END_SESSION_ENDPOINT',
                         'http://example.com/a/end-session')
    def test_can_log_out_a_user_from_the_application_and_the_authorization_server(
            self, mocked_logout, client):
        User.objects.create_user('foo', password='insecure')
        client.login(username='foo', password='insecure')
        session = client.session
        session['oidc_auth_id_token'] = 'idtoken'
        session.save()
        url = reverse('oidc_rp:oidc_end_session')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        assert response.url.startswith('http://example.com/a/end-session')
        parsed_parameters = parse_qs(urlparse(response.url).query)
        assert parsed_parameters['post_logout_redirect_uri'] == ['http://testserver/', ]
        assert parsed_parameters['id_token_hint'] == ['idtoken', ]
        assert mocked_logout.call_count == 1

    @unittest.mock.patch('django.contrib.auth.logout')
    @override_settings(LOGOUT_REDIRECT_URL='/logout')
    def test_can_log_out_a_user_from_the_application_without_end_session_endpoint(
            self, mocked_logout, client):
        User.objects.create_user('foo', password='insecure')
        client.login(username='foo', password='insecure')
        url = reverse('oidc_rp:oidc_end_session')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        assert response.url == '/logout'
        assert mocked_logout.call_count == 1

    @unittest.mock.patch('django.contrib.auth.logout')
    @override_settings(LOGOUT_REDIRECT_URL='/logout')
    def test_silently_works_for_anonymous_users(self, mocked_logout, client):
        url = reverse('oidc_rp:oidc_end_session')
        response = client.get(url, follow=False)
        assert response.status_code == 302
        assert response.url == '/logout'
        assert not mocked_logout.call_count
