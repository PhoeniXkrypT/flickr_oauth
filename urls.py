from django.conf.urls import patterns, include, url
from authfl.views import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
	url(r'^login/$', log),
  url(r'^register/$', register),
	url(r'^home/$', home),
	url(r'^base/$', base),

)
