"""
    Project base URL configuration
    ==============================

    For more information on this file, see https://docs.djangoproject.com/en/1.10/topics/http/urls/

"""

from django.conf.urls import include, url
from django.contrib import admin

js_info_dict = {
    'packages': ('base', ),
}

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^oidc/', include('oidc_rp.urls')),
]
