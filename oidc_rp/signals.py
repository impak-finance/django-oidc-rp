from django.dispatch import Signal


oidc_user_created = Signal(providing_args=['request', 'oidc_user'])
