from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.template import RequestContext
import settings
import oauth2 as oauth
from forms import *
import flickr_api
import requests
from bs4 import BeautifulSoup

def home(request):

	flickr_api.set_keys(api_key = settings.API_KEY, api_secret = settings.API_SECRET)
	authorize_url = flickr_api.auth.AuthHandler(callback = "http://127.0.0.1:8000/base/") 
	settings.authorize_url=authorize_url
	perms = "read"
	url = authorize_url.get_authorization_url(perms)
	print url
	return HttpResponseRedirect(url)
	
	return render (request,'home.html')
	
	
def base(request):
	state="HOMEPAGE"
	
	oauth_verifier = request.GET.get('oauth_verifier')
	print ">>>>", oauth_verifier
	authorize_url=settings.authorize_url
	authorize_url.set_verifier(oauth_verifier)
	flickr_api.set_auth_handler(authorize_url)
	
	print
	user = flickr_api.test.login()
	print "User Info : ", user
	photos = user.getPhotos()
	print photos
	print "Photo No: ",photos.info.total
	
	return render(request,'base.html')
	

def log(request):
    state = "LOGIN PAGE !!!"
    username = password = ''
    if request.method=='POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
     
    return render_to_response('login.html',{'state':state, 'username': username},RequestContext(request))

def register(request):
    try:
        context_instance=RequestContext(request)
        if request.method == 'POST':
            user_form = registerform(request.POST)
            login_form = loginform(request.POST)
        return render_to_response('reg.html',{'user_form' : registerform(),'login_form' : loginform(),
                                                        'page':'register'},                                                        RequestContext(request))
    except KeyError:
        pass
