from django.db import models


class FrontierUserData(models.Model):
    customer_id = models.BigIntegerField(primary_key=True, unique=True)
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    platform = models.CharField(max_length=255)

    def __str__(self):
        return str(self.customer_id)


class DiscordUserData(models.Model):
    id = models.BigIntegerField(primary_key=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    discriminator = models.CharField(max_length=255, null=True, blank=True)
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

    def __str__(self):
        return self.username
