#####################
Django REST framework
#####################

The ``rest_framework`` contrib package allows to add support for authentication using Bearer tokens
to your API endpoints. You can easily activate the related authentication backend by adding it to
the DRF's ``DEFAULT_AUTHENTICATION_CLASSES`` setting as follows:

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
