###############
Getting started
###############

Requirements
============

* `Python`_ 3.4, 3.5 and 3.6
* `Django`_ 1.11.x and 2.0.x
* `Django-jsonfield`_ 2.0 or higher
* `Pyjwkest`_ 1.4 or higher
* `Requests`_ 2.0 or higher

Installation
============

To install Django-oidc-rp, please use pip_ (or pipenv_) as follows:

.. code-block:: shell

    $ pip install django-oidc-rp

Project configuration
=====================

Django settings
---------------

First you need to update your ``INSTALLED_APPS`` so that it includes the ``oidc_rp`` Django
application:

.. code-block:: python

    INSTALLED_APPS = (
        # Other apps
        'oidc_rp',
    )

You can now add the ``oidc_rp.backends.OIDCAuthBackend`` authentication backend to your project's
authentication backends:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
        'oidc_rp.backends.OIDCAuthBackend',
    )

Then add the ``oidc_rp.context_processors.oidc`` context processor to your ``TEMPLATES`` setting:

.. code-block:: python

    TEMPLATES = [
        {
            # ...
            'OPTIONS': {
                'context_processors': [
                    # Other context processors
                    'oidc_rp.context_processors.oidc',
                ],
            },
        },
    ]

Finally add the ``oidc_rp.middleware.OIDCRefreshIDTokenMiddleware`` middleware to your
``MIDDLEWARE`` setting:

.. code-block:: python

    MIDDLEWARE = (
        # Other middlewares
        'oidc_rp.middleware.OIDCRefreshIDTokenMiddleware',
    )

.. note::

    This middleware will ensure that the access tokens of your users are being refreshed by the OIDC
    provider periodically.

Django-oidc-rp settings
-----------------------

At this point a client should've been configured on the identity provider you're using.
Use the values provided by your OpenID Connect provider (OP) to configure the following settings:

.. code-block:: python

    OIDC_RP_PROVIDER_ENDPOINT = 'https://id.example.com/a/'
    OIDC_RP_CLIENT_ID = '<CLIENT_ID>'
    OIDC_RP_CLIENT_SECRET = '<CLIENT_SECRET>'

.. warning::

    The values you put in the ``OIDC_RP_CLIENT_ID`` and ``OIDC_RP_CLIENT_SECRET`` are secret values.
    They should be kept secret, and therefore out of version control.

The complete list of settings provided by django-oidc-rp can be found in the :doc:`settings`
section.

.. tip::

    Trying to add support for OpenID Connect authentication to your Django REST framework API? Have
    a look at the :doc:`contrib_packages/drf` contrib package documentation.

Database and migrations
=======================

Just use the ``migrate`` command to install the models:

.. code-block:: shell

    $ python manage.py migrate

.. note::

    Django-oidc-rp provides a single model used to store the user information provided by the
    configured OpenID Connect Provider (OP). This model also associates with each Django user a
    subject identifier (sub) - also provided by the OIDC provider in order to uniquely identify a
    subject accrossa the relying parties.


URLs configuration
==================

Finally you have to update your main ``urls.py`` module in order to include the OIDC RP's URLs:

.. code-block:: python

    urlpatterns = patterns(
        url(r'^oidc/', include('oidc_rp.urls')),
        # ...
    )


Authentication links in templates
=================================

Last but not least, you have to replace your login/logout links in your templates in order to use
the ones provided by django-oidc-rp. Here is an example:

.. code-block:: HTML

    <html>
      <body>
        {% if user.is_anonymous %}
        <a href="{% url 'oidc_auth_request' %}">Login</a>
        {% else %}
        <a href="{% url 'oidc_end_session' %}">Logout</a>
        {% endif %}
      </body>
    </html>

|

*Congrats! You’re in!*

.. _pip: https://github.com/pypa/pip
.. _pipenv: https://github.com/pypa/pipenv
.. _Python: https://www.python.org
.. _Django: https://www.djangoproject.com
.. _Django-jsonfield: https://pypi.org/project/jsonfield/
.. _Pyjwkest: https://pypi.org/project/pyjwkest/
.. _Requests: https://pypi.org/project/requests/
