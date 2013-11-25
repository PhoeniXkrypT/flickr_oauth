from django.db import models


class Client_Flickr(models.Model):
  user = models.OneToOneField('Client')
  flickr_id = models.DecimalField(max_digits=20, decimal_places=0,null=True)
  access_token = models.CharField(max_length=200,null=True)
  access_token_secret = models.CharField(max_length=200,null=True)
  flickr_username = models.CharField(max_length=200,null=True)

  def __unicode__(self):
    return self.user.user.username


class register(models.Model):
    name = models.CharField(max_length=100,blank=False, unique=True)
    username = models.CharField(max_length=100,blank=False, unique=True,primary_key=True)
    email = models.EmailField(blank=False, unique=True)
    class Meta:
        db_table= 'reg'
        ordering = ['username','name']

    def __unicode__(self):
                return self.email

    def get_absolute_url(self):
                return "/users/%s" % self.username

class login(models.Model):
    username = models.ForeignKey(register, max_length=100, primary_key=True,
                                blank=False,unique=True)
    password = models.CharField(max_length=100, blank=False)

    class Meta:
        db_table= 'login'

    def __unicode__(self):
        return self.username
