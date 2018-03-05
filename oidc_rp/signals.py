from django.dispatch import Signal


request_dispatcher = Signal(providing_args=['request'])
