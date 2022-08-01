import datetime as dt
import os
import unittest.mock
from calendar import timegm

import httpretty
import pytest
from django.core.exceptions import SuspiciousOperation
from jwkest.jwk import KEYS, RSAKey
from jwkest.jws import JWS

from oidc_rp.conf import settings as oidc_rp_settings
from oidc_rp.utils import validate_and_return_id_token


FIXTURE_ROOT = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestValidateAndReturnIDTokenUtility:
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

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_can_validate_and_decode_an_id_token(self):
        jws = self.generate_jws()
        id_token = validate_and_return_id_token(jws, 'nonce')
        assert id_token['iss'] == 'http://example.com/a/'
        assert id_token['nonce'] == 'nonce'
        assert id_token['aud'] == ['client_id']
        assert id_token['azp'] == 'client_id'
        assert id_token['sub'] == '1234'

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    @unittest.mock.patch('oidc_rp.conf.settings.USE_NONCE', False)
    def test_can_validate_and_decode_an_id_token_when_nonces_are_disabled(self):
        jws = self.generate_jws()
        id_token = validate_and_return_id_token(jws, validate_nonce=False)
        assert id_token['iss'] == 'http://example.com/a/'
        assert id_token['aud'] == ['client_id']
        assert id_token['azp'] == 'client_id'
        assert id_token['sub'] == '1234'

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_incorrect_id_token(self):
        id_token = validate_and_return_id_token('dummy')
        assert id_token is None

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_an_invalid_iss(self):
        jws = self.generate_jws(iss='http://dummy.com')
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_an_invalid_client_id(self):
        jws = self.generate_jws(client_key='unknown')
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_multiple_audiences_but_no_authorized_party(self):
        jws_dict = self.generate_jws_dict()
        jws_dict['aud'] = [oidc_rp_settings.CLIENT_ID, '2']
        jws_dict.pop('azp')
        jws = JWS(jws_dict, jwk=self.key, alg='RS256').sign_compact()
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_an_authorized_party(self):
        jws = self.generate_jws(azp='dummy')
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_whose_signature_has_expired(self):
        jws = self.generate_jws(expiration_dt=dt.datetime.utcnow() - dt.timedelta(minutes=40))
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_an_invalid_nbf_value(self):
        jws = self.generate_jws(nbf=dt.datetime.utcnow() + dt.timedelta(minutes=100))
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_which_is_too_aged(self):
        jws = self.generate_jws(issue_dt=dt.datetime.utcnow() - dt.timedelta(minutes=100))
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_whose_nonce_is_not_valid(self):
        jws = self.generate_jws(nonce='invalidnonce')
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws)

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_access_token_and_no_at_hash(self):
        jws = self.generate_jws()
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws, 'nonce', access_token="accesstoken")

    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_ID', 'client_id')
    @unittest.mock.patch('oidc_rp.conf.settings.CLIENT_SECRET', 'client_secret')
    def test_cannot_validate_an_id_token_with_access_token_and_incorrect_at_hash(self):
        jws = self.generate_jws(at_hash='incorrect_hash')
        with pytest.raises(SuspiciousOperation):
            validate_and_return_id_token(jws, 'nonce', access_token="accesstoken")
