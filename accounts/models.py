from django.contrib.auth.models import AbstractUser
from django.db import models

from accounts.managers import UserManager

GENDER_CHOICES = (
    ('male', 'Male'),
    ('female', 'Female'))


class User(AbstractUser):
    username = None
    role = models.CharField(max_length=12, error_messages={
        'required': "Role must be provided"
    })
    gender = models.CharField(max_length=10, blank=True, null=True, default="")
    email = models.EmailField(unique=True, blank=False,
                              error_messages={
                                  'unique': "A user with that email already exists.",
                              })
    middle_name = models.CharField(max_length=78, blank=True, null=True, default="")
    job_title = models.CharField(max_length=78, blank=True, null=True, default="")
    tot_exp_yr = models.CharField(max_length=78, blank=True, null=True, default="")
    tot_exp_mon = models.CharField(max_length=78, blank=True, null=True, default="")
    dob_city = models.CharField(max_length=78, blank=True, null=True, default="")
    dob_state = models.CharField(max_length=78, blank=True, null=True, default="")
    dob = models.CharField(max_length=78, blank=True, null=True, default="")
    city= models.CharField(max_length=78, blank=True, null=True, default="")
    state = models.CharField(max_length=78, blank=True, null=True, default="")
    country = models.CharField(max_length=78, blank=True, null=True, default="")
    pin = models.CharField(max_length=78, blank=True, null=True, default="")
    tel= models.CharField(max_length=78, blank=True, null=True, default="")
    mob= models.CharField(max_length=78, blank=True, null=True, default="")
    address= models.CharField(max_length=78, blank=True, null=True, default="")
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __unicode__(self):
        return self.email

    objects = UserManager()
