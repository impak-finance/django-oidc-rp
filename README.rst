impak-django-oidc-rp
====================

.. image:: https://travis-ci.org/impak-finance/django-oidc-rp.svg?branch=master
    :target: https://travis-ci.org/impak-finance/django-oidc-rp

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

.. code-block:: shell

    $ pip install impak-django-oidc-rp

Once installed you just need to add ``oidc_rp`` to ``INSTALLED_APPS`` in your project's settings
module:

.. code-block:: python

    INSTALLED_APPS = (
        # other apps
        'oidc_rp',
    )

Then install the models:

.. code-block:: shell

    $ python manage.py migrate oidc_rp

You can now add the ``oidc_rp.backends.OIDCAuthBackend`` to your project's authentication backends:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
        'oidc_rp.backends.OIDCAuthBackend',
    )

And the ``oidc_rp.middleware.OIDCRefreshIDTokenMiddleware`` to your ``MIDDLEWARE`` setting:

.. code-block:: python

    MIDDLEWARE = (
        # other middlewares
        'oidc_rp.middleware.OIDCRefreshIDTokenMiddleware',
    )

Of course at this point a client should've been configured on the identity provider you're using.
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

Django REST framework
~~~~~~~~~~~~~~~~~~~~~

A contrib module is available to add support for authentication using Bearer tokens to your API
endpoints. You can easily activate the related backend by adding it to the
``DEFAULT_AUTHENTICATION_CLASSES`` setting as follows:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_PERMISSION_CLASSES': (
            'rest_framework.permissions.IsAuthenticated',
        ),
        'DEFAULT_AUTHENTICATION_CLASSES': (
            # ...
            'oidc_rp.contrib.rest_framework.authentication.BearerTokenAuthentication',
        ),
    }

Authors
-------

impak Finance <tech@impakfinance.com>.

License
-------

MIT. See ``LICENSE`` for more details.
