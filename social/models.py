from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class SocialUser(models.Model):
    auth_user = models.OneToOneField(User, db_column = u'Id')

    #Twitter
    twitter_request_token = models.CharField(max_length = 255,  blank = True, null = True)
    twitter_request_secret = models.CharField(max_length = 255,  blank = True, null = True)
    twitter_access_token = models.CharField(max_length = 255,  blank = True, null = True)
    twitter_access_secret = models.CharField(max_length = 255,  blank = True, null = True)

