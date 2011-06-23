from django.conf.urls.defaults import *
import views

urlpatterns = patterns('',

    # Twitter
    url('^twitter/auth/$',
        views.social_twitter.auth,
        name='twitter_auth'
     ),

    url('^twitter/access_granted/$',
        views.social_twitter.access_granted,
        name='twitter_access_granted'
     ),

    url('^twitter/post/$',
        views.social_twitter.post,
        name='twitter_post'
     )

)
#
#urlpatters += patterns('facebook',
#
#    # Facebook
#    url('^auth_code/$',
#        views.facebook_auth_code,
#        name='facebook_auth_code'
#     ),
#
#     url('^post/$',
#        views.facebook_post,
#        name='facebook_post'
#     )
#)
