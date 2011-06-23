# Create your views here.
from django.template.context import RequestContext
from django.shortcuts import render_to_response
from poseidon.models import HttpLog
import urlparse
import oauth2 as oauth
import logging
from django.http import HttpResponseRedirect
import twitter
import traceback
import random
from django.core.urlresolvers import reverse
import urllib2
from django.contrib.sites.models import Site
import datetime
import urllib
import facebook
from django.core.cache import cache

consumer_key = 'TFKGMSHZ2VyHIR257Q8xMw'
consumer_secret = 'kdye8xNwhXLWmF9u8I38j662vSrSiNz6U3GMtpwQ'
request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'

consumer = oauth.Consumer(consumer_key, consumer_secret)
client = oauth.Client(consumer)

def twitter_request_token(request):
    # Step 1: Get a request token. This is a temporary token that is used for
    # having the user authorize an access token and to sign the request to obtain
    # said access token.
    resp, content = client.request(request_token_url, "GET")
    if resp['status'] != '200':
        raise Exception("Invalid response %s." % resp['status'])

    request_token = dict(urlparse.parse_qsl(content))

    logging.info("Request Token:")
    logging.info("    - oauth_token        = %s" % request_token['oauth_token'])
    logging.info("    - oauth_token_secret = %s" % request_token['oauth_token_secret'])

    cache.put('twitter_oauth_token', request_token['oauth_token'])
    cache.put('twitter_oauth_token_secret', request_token['oauth_token_secret'])

    # Step 2: Redirect to the provider. Since this is a CLI script we do not
    # redirect. In a web application you would redirect the user to the URL
    # below.

    url = "%s?oauth_token=%s" % (authorize_url, request_token['oauth_token'])

    logging.info(url)


    return HttpResponseRedirect('/')

def twitter_access_token(request):
    oauth_token = cache.get('oauth_token')
    oauth_token_secret = cache.get('oauth_token_secret')

    oauth_verifier = 'QNYvteF7vxoifs2nF4FJt8wWIlPjKPrZcsUgIIQHqw'

    # Step 3: Once the consumer has redirected the user back to the oauth_callback
    # URL you can request the access token the user has approved. You use the
    # request token to sign this request. After this is done you throw away the
    # request token and use the access token returned. You should store this
    # access token somewhere safe, like a database, for future use.
    token = oauth.Token(oauth_token,oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urlparse.parse_qsl(content))

    logging.info("Access Token:")
    logging.info("    - oauth_token        = %s" % access_token['oauth_token'])
    logging.info("    - oauth_token_secret = %s" % access_token['oauth_token_secret'])
    logging.info("You may now access protected resources using the access tokens above.")


    cache.put('twitter_access_token', access_token['oauth_token'])
    cache.put('twitter_access_token_secret', access_token['oauth_token_secret'])

    return HttpResponseRedirect('/')



def twitter_post(request):
    access_token = cache.get('twitter_access_token')
    access_token_secret = cache.get('twitter_access_token_secret')
    api = twitter.Api(consumer_key=consumer_key,consumer_secret=consumer_secret, access_token_key=access_token, access_token_secret=access_token_secret)
    try:
        api.VerifyCredentials()
        status = api.PostUpdate('I love python-twitter! #gowestthevillagepeople http://goo.gl/rF70o  ' + str(random.randint(0,10)))
    except twitter.TwitterError, ex:
        logging.error(traceback.format_exc())
        if ex.message == u'Could not authenticate with OAuth.':
            logging.error('User has revoked authentication')
    else:
        logging.info(status.text)

    return HttpResponseRedirect('/')


def facebook_auth_code(request):
    """
    The URL Facebook loads once the user has granted access rights to the app
    in the Facebook popup window
    """
    # 1. Get the AUTH CODE
    auth_code = request.GET.get('code','')
    logging.info('Authorisation code: ' + str(auth_code))

    client_id = '151451354927884'
    client_secret = '56126bbfd7565cb2f0b9072d30999bb3'

    url = reverse('facebook_auth_code')
    domain = 'poseidon-blas.appspot.com'
    redirect_uri = 'http://%s%s' % (domain, url)

    auth_url = ('https://graph.facebook.com/oauth/access_token?'
                'client_id=%(client_id)s&redirect_uri=%(redirect_uri)s&'
                'client_secret=%(client_secret)s&code=%(auth_code)s' %
                {'client_id': client_id, 'client_secret': client_secret,
                 'redirect_uri': redirect_uri, 'auth_code': auth_code}
                )

    logging.info('Auth URL: ' + auth_url)

    # 2. Get (and store) the ACCESS TOKEN
    response = urllib2.urlopen(auth_url)
    if response.code == 400:
        # error
        logging.error(response.read())

#        {
#           "error": {
#              "type": "OAuthException",
#              "message": "Error validating verification code."
#           }
#        }
    else:
        #success
        contents = response.read()
        contents = contents.split('&')
        values = {}
        for part in contents:
            key, value = part.split('=')
            values[key] = value
        logging.info('Received access token: ' + values.get('access_token'))
        logging.info('Expires: ' + values.get('expires'))
        logging.info('Expires: ' + str(datetime.datetime.now() + datetime.timedelta(seconds=int(values.get('expires')))))

        cache.set('facebook_oauth_token', values.get('access_token'), int(values.get('expires')))

    return HttpResponseRedirect('/')


def facebook_post(request):
    graph = facebook.GraphAPI(cache.get('facebook_oauth_token'))
    profile = graph.get_object("me")
    friends = graph.get_connections("me", "friends")
    graph.put_object("me", "feed", message="I am writing on my wall!")

    logging.info(profile)
    logging.info(friends)
#
#
#    values = {}
#    values['access_token'] =
#    values['message'] = 'test test'
#
#    data = urllib.urlencode(values)
#    url = 'https://graph.facebook.com/craig.blaszczyk/feed'
#    req = urllib2.Request(url, data)
#    resp = urllib2.urlopen(req)
#
#    logging.info(resp.code)
#logging.info(resp.read())

    return HttpResponseRedirect('/')

