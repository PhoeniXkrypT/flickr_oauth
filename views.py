from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.template import RequestContext
import settings
import oauth2 as oauth
import urlparse
import time
from hashlib import sha1
import hmac
import binascii
import httplib2
from forms import *

def flickr_connect(request):
	flickr_consumer_key = settings.FLICKR_CONSUMER_KEY
	flickr_consumer_secret = settings.FLICKR_CONSUMER_SECRET
	
	try:
		next = '/home/'
		if('redirect' in request.session):
			next = request.session['redirect']
      			del request.session['redirect']
			flickr = Client_Twitter.objects.get(user=request.user.get_profile())
       			#return HttpResponseRedirect('/account/login?next='+next)
    			return HttpResponseRedirect(next)
	except Exception:
		print "NOOOO"

	if ('oauth_verifier' not in request.GET):
		client = oauth.Client(consumer)
		resp, content = client.request(request_token_url, "GET")
		request_token = dict(urlparse.parse_qsl(content))
		print "The request token is " + str(request_token)
		roauth_token = request_token['oauth_token']
		roauth_token_secret = request_token['oauth_token_secret']
		request.session['roauth_token'] = roauth_token
		request.session['roauth_token_secret'] = roauth_token_secret
		new_authorize_url = authorize_url+'?oauth_token='+request_token['oauth_token']
		print "new auth url is " + new_authorize_url
        	return HttpResponseRedirect(new_authorize_url)

def home(request):
	flickr_consumer_key = settings.FLICKR_CONSUMER_KEY
	flickr_consumer_secret = settings.FLICKR_CONSUMER_SECRET
	url = "https://www.flickr.com/services/oauth/request_token"
	params = {
		'oauth_timestamp': str(int(time.time())),
		'oauth_signature_method':"HMAC-SHA1",
		'oauth_version': "1.0",
		'oauth_callback': "http://127.0.0.1:8000/home/",
		'oauth_nonce': oauth.generate_nonce(),
		'oauth_consumer_key': flickr_consumer_key
		}
	consumer = oauth.Consumer(key=flickr_consumer_key, secret=flickr_consumer_secret)
	req = oauth.Request(method="GET", url=url, parameters=params)

# Create the signature
	signature = oauth.SignatureMethod_HMAC_SHA1().sign(req,consumer,None)

# Add the Signature to the request
	req['oauth_signature'] = signature

# Make the request to get the oauth_token and the oauth_token_secret
	h = httplib2.Http(".cache")
	resp, content = h.request(req.to_url(), "GET")
	
#	request_token_url=content


	authorize_url = "http://www.flickr.com/services/oauth/authorize"

#parse the content
	request_token = dict(urlparse.parse_qsl(content))

	print "Request Token:"
	print "    - oauth_token        = %s" % request_token['oauth_token']
	print "    - oauth_token_secret = %s" % request_token['oauth_token_secret']
	print

# Create the token object with returned oauth_token and oauth_token_secret
	token = oauth.Token(request_token['oauth_token'],
		request_token['oauth_token_secret'])

# You need to authorize this app via your browser.
	print "Go to the following link in your browser:"
	print "%s?oauth_token=%s&perms=read" % (authorize_url, request_token['oauth_token'])


# Once you get the verified pin, input it
	accepted = 'n'
	while accepted.lower() == 'n':
    		accepted = raw_input('Have you authorized me? (y/n) ')
	oauth_verifier = raw_input('What is the PIN? ')

#set the oauth_verifier token
	token.set_verifier(oauth_verifier)

	access_token_url = "http://www.flickr.com/services/oauth/access_token"

# Now you need to exchange your Request Token for an Access Token
# Set the base oauth_* parameters along with any other parameters required
# for the API call.
	access_token_parms = {
		'oauth_consumer_key': flickr_consumer_key,
		'oauth_nonce': oauth.generate_nonce(),
		'oauth_signature_method':"HMAC-SHA1",
		'oauth_timestamp': str(int(time.time())),
		'oauth_token':request_token['oauth_token'],
		'oauth_verifier' : oauth_verifier
	}

#setup request
	req = oauth.Request(method="GET", url=access_token_url,
		parameters=access_token_parms)

#create the signature
	signature = oauth.SignatureMethod_HMAC_SHA1().sign(req,consumer,token)

# assign the signature to the request
	req['oauth_signature'] = signature

#make the request
	h = httplib2.Http(".cache")
	resp, content = h.request(req.to_url(), "GET")

#parse the response
	access_token_resp = dict(urlparse.parse_qsl(content))

#	access_token_url = 'https://www.flickr.com/services/oauth/access_token'
#	authorize_url = 'https://www.flickr.com/services/oauth/authorize'
	consumer = oauth.Consumer(flickr_consumer_key,flickr_consumer_secret)
	
	if (request.GET['oauth_verifier'] != "" ):
		oauth_verifier = request.GET['oauth_verifier']
		token = oauth.Token(request.session.get('roauth_token', None),request.session.get('roauth_token_secret', None))
		token.set_verifier(oauth_verifier)
		client = oauth.Client(consumer, token)
	 
		resp, content = client.request(access_token_url, "POST")
		access_token = dict(urlparse.parse_qsl(content))
 
 
		del request.session['roauth_token']
		del request.session['roauth_token_secret']
 
		oauth_token = access_token['oauth_token']
		oauth_token_secret = access_token['oauth_token_secret']
		userid = access_token['user_id']
		screenname = access_token['screen_name']
		print "Screenname=%s, userid=%s, oauth_token=%s, oauth_secret=%s" %(screenname, userid, oauth_token, oauth_token_secret)
	return render (request,'home.html')

def log(request):
    state = "LOGIN PAGE !!"
    username = password = ''
    if request.method=='POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                state = "You're logged in!"
            else:
                state = "Please contact the site admin."
        else:
            state = "Username and/or password incorrect."

    return render_to_response('login.html',{'state':state, 'username': username},RequestContext(request))

def register(request):
    try:
        context_instance=RequestContext(request)
        if request.method == 'POST':
            user_form = registerform(request.POST)
            login_form = loginform(request.POST)

            user_is_valid = user_form.is_valid()
            login_is_valid = login_form.is_valid()

            if user_is_valid and login_is_valid:
                cleaned_user_data = user_form.cleaned_data
                cleaned_login_data = login_form.cleaned_data
                cleaned_username = cleaned_login_data['username']
                cleaned_password = cleaned_login_data['password']
                cleaned_email = cleaned_user_data['email']

                login_instance = Login(cleaned_username, cleaned_password, cleaned_email)

                user_form.save()
                login_instance.save()

                return HttpResponseRedirect('/home/')

            else:
                return render_to_response('reg.html',
                                            {'user_form':user_form,
                                            'login_form':login_form,
                                            'page':'register'},
                                        RequestContext(request))

        return render_to_response('reg.html',
                                                    {'user_form' : registerform(),
                                                        'login_form' : loginform(),
                                                        'page':'register'},
                                                        RequestContext(request))
    except KeyError:
        return error_key(request)
