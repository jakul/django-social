# Create your views here.
from django.template.context import RequestContext
from django.shortcuts import render_to_response
try:
    from urlparse import parse_qsl
except ImportError:
    #Python 2.5
    from cgi import parse_qsl
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
from django.contrib.auth.decorators import login_required
from social.models import User, SocialUser

consumer_key = 'TFKGMSHZ2VyHIR257Q8xMw'
consumer_secret = 'kdye8xNwhXLWmF9u8I38j662vSrSiNz6U3GMtpwQ'
request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'

consumer = oauth.Consumer(consumer_key, consumer_secret)
client = oauth.Client(consumer)

logger = logging.getLogger()
#logger.setLevel(logging.DEBUG)


@login_required
def auth(request):
    # Step 1: Get a request token. This is a temporary token that is used for
    # having the user authorize an access token and to sign the request to obtain
    # said access token.
    resp, content = client.request(request_token_url, "GET")
    if resp['status'] != '200':
        raise Exception("Invalid response %s." % resp['status'])

    request_token = dict(parse_qsl(content))
    logger.info("Request Token:")
    logger.info("    - oauth_token        = %s" % request_token['oauth_token'])
    logger.info("    - oauth_token_secret = %s" % request_token['oauth_token_secret'])

    logger.info(request_token)


    oauth_token = request_token['oauth_token']
    oauth_token_secret = request_token['oauth_token_secret']


    user, __ = SocialUser.objects.get_or_create(auth_user=request.user)
    user.twitter_request_token = oauth_token
    user.twitter_request_secret = oauth_token_secret
    user.save()

    # Step 2: Redirect to the provider. Since this is a CLI script we do not
    # redirect
    url = "%s?oauth_token=%s" % (authorize_url, request_token['oauth_token'])
    return HttpResponseRedirect(url)


def access_granted(request):
    """
    Uses the return info from twitter to convert the request token into an
    access token
    """

    logging.info(request.GET, request)

    oauth_token = request.GET.get('oauth_token')
    oauth_verifier = request.GET.get('oauth_verifier')
#    oauth_verifier = 'QNYvteF7vxoifs2nF4FJt8wWIlPjKPrZcsUgIIQHqw'


    user = SocialUser.objects.get(twitter_request_token=oauth_token)

    # Step 3: Once the consumer has redirected the user back to the oauth_callback
    # URL you can request the access token the user has approved. You use the
    # request token to sign this request. After this is done you throw away the
    # request token and use the access token returned. You should store this
    # access token somewhere safe, like a database, for future use.
    token = oauth.Token(oauth_token,user.twitter_request_secret)
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")
    oauth_access_token = dict(parse_qsl(content))

    logger.error(oauth_access_token)
    access_token = oauth_access_token['oauth_token']
    access_token_secret = oauth_access_token['oauth_token_secret']

    logger.info("Access Token:")
    logger.info("    - oauth_token        = %s" % access_token)
    logger.info("    - oauth_token_secret = %s" % access_token_secret)
    logger.info("You may now access protected resources using the access tokens above.")

    user.twitter_access_token = access_token;
    user.twitter_access_secret = access_token_secret;
    user.save()

    return HttpResponseRedirect('/')

@login_required
def post(request, message=None):
    if message is None:
        message = 'I\'m posting using django-twitter'

    #TODO: Verify that the user has granted access for twitter
    user = SocialUser.objects.get(auth_user=request.user)

    if user.twitter_access_token is None:
        raise Exception('User has not authorised twitter')

    api = twitter.Api(
        consumer_key=consumer_key, consumer_secret=consumer_secret,
        access_token_key= user.twitter_access_token,
        access_token_secret=user.twitter_access_secret,
        cache=None #for google app engine
        #see http://code.google.com/p/python-twitter/issues/detail?id=59
        )

    try:
        api.VerifyCredentials()
        status = api.PostUpdate(message)
    except twitter.TwitterError, ex:
        logger.error(traceback.format_exc())
        if ex.message == u'Could not authenticate with OAuth.':
            logger.error('User has revoked authentication')
    else:
        logger.info(status.text)

    return HttpResponseRedirect('/')

