import unittest.mock
from hashlib import sha224, sha256

from django.contrib.sites.shortcuts import get_current_site

from oidc_rp.context_processors import oidc as oidc_ct


@unittest.mock.patch(
    'oidc_rp.conf.settings.UNAUTHENTICATED_SESSION_MANAGEMENT_KEY', 'dummyKey')
def test_oidc_context_processor_can_generate_appropriate_context_values(rf):
    request = rf.get('/')
    ctx = oidc_ct(request)
    assert ctx['oidc_client_id'] == 'DUMMY_CLIENT_ID'
    assert ctx['oidc_op_endpoint'] == 'http://example.com/a/'
    assert ctx['oidc_op_url'] == 'http://example.com'
    state, salt = ctx['oidc_anonymous_session_state'].split('.')
    computed_state = '{client_id} {origin} {browser_state} {salt}'.format(
        client_id='DUMMY_CLIENT_ID',
        origin='{}://{}'.format(request.scheme, get_current_site(request).domain),
        browser_state=sha224('dummyKey'.encode('utf-8')).hexdigest(),
        salt=salt)
    computed_state = sha256(computed_state.encode('utf-8')).hexdigest() + '.' + salt
    assert computed_state == ctx['oidc_anonymous_session_state']
