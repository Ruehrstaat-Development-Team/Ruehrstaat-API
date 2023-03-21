from django.db import models

from django.contrib.auth.models import AbstractUser

from .managers import DiscordUserAuthManager

class User(AbstractUser):
    objects = DiscordUserAuthManager()

    id = models.BigIntegerField(primary_key=True)
    discord_tag = models.CharField(max_length=255, null=True, blank=True)
    avatar = models.CharField(max_length=255, null=True, blank=True)
    avatar_url = models.CharField(max_length=255, null=True, blank=True)
    locale = models.CharField(max_length=255, null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    email = models.CharField(max_length=255, null=True, blank=True)
    flags = models.IntegerField(null=True, blank=True)
    premium_type = models.IntegerField(null=True, blank=True)
    public_flags = models.IntegerField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return self.username
    

