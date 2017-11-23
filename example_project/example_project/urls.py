"""
    Project base URL configuration
    ==============================

    For more information on this file, see https://docs.djangoproject.com/en/1.10/topics/http/urls/

"""

from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin


urlpatterns = [
    # Internationalization.
    url(r'^i18n/', include('django.conf.urls.i18n')),

    # Apps
    url(r'^oidc/', include('oidc_rp.urls')),
]

urlpatterns += i18n_patterns(
    # Admin
    url(r'^admin/', admin.site.urls),

    # Apps
    url(r'^', include('example.public.urls')),
)

if settings.DEBUG:
    # In DEBUG mode, serve media files through Django.
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns
    from django.views import static
    urlpatterns += staticfiles_urlpatterns()
    # Remove leading and trailing slashes so the regex matches.
    media_url = settings.MEDIA_URL.lstrip('/').rstrip('/')
    urlpatterns += [
        url(r'^%s/(?P<path>.*)$' % media_url, static.serve,
            {'document_root': settings.MEDIA_ROOT}),
    ]
