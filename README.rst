impak-django-oidc-rp
====================

.. image:: https://circleci.com/gh/impak-finance/impak-django-oidc-rp.svg?style=svg&circle-token=f5c541df21a216cdbfa6fc761dd8f68dec51766a
    :target: https://circleci.com/gh/impak-finance/impak-django-oidc-rp

|

**Impak-django-oidc-rp** is a lightweight - server side OpenID Connect Relying Party (RP/Client)
implementation for Django. It allows to easily integrate an OpenID Connect provider as the
authentication source in a Django project.

Main requirements
-----------------

Python 3.4+, Django 1.11+.

Installation
------------

Just run:

::

    $ pip install impak-django-oidc-rp

Once installed you just need to add ``oidc_rp`` to ``INSTALLED_APPS`` in your project's settings
module:

.. code-block:: python

    INSTALLED_APPS = (
        # other apps
        'oidc_rp',
    )

Then add the ``oidc_rp.backends.OIDCAuthBackend`` to your project's authentication backends:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
        'oidc_rp.backends.OIDCAuthBackend',
    )

Of course at this point a client should've been configured in the identity provider you're using.
Use the values provided by your OpenID Connect provider (OP) to configure the following settings:

.. code-block:: python

    OIDC_RP_PROVIDER_ENDPOINT = 'https://id.example.com/a/'
    OIDC_RP_CLIENT_ID = 'CLIENT_ID'
    OIDC_RP_CLIENT_SECRET = 'INSECURE_CLIENT_SECRET'

Next, add the following inclusion to your root ``urls.py``:

.. code-block:: python

    urlpatterns = patterns(
        url(r'^oidc/', include('oidc_rp.urls')),
        # ...
    )

Finally you'll have to add the sign in / sign out URLs to your project's templates.
``{% url 'oidc_auth_request' %}`` should be used to start the authentication process involving your
OpenID Connect provider. ``{% url 'oidc_end_session' %}`` should be used to log out the current user
and potentially end his session at the OP level.

*Congrats! You’re in!*

Authors
-------

impak Finance <hello@impakfinance.com>.

License
-------

BSD. See ``LICENSE`` for more details.
