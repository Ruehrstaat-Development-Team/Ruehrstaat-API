from django.db import models

from rest_framework_api_key.models import AbstractAPIKey

from carriers.models import Carrier

# Create your models here.


class ApiKey(AbstractAPIKey):
    hasReadAccessTo = models.ManyToManyField(Carrier, blank=True, default=None, related_name="hasReadAccessTo")
    hasReadAccessToAll = models.BooleanField(default=False, null=False, blank=False)
    # field to indicate if key can only be used for specific carrier ids from Carrier model -> ids, default is None which means all carriers
    hasWriteAccessTo = models.ManyToManyField(Carrier, blank=True, default=None, related_name="hasWriteAccessTo")
    hasWriteAccessToAll = models.BooleanField(default=False, null=False, blank=False)


#add a model for logging changes made using the api
class ApiLog(models.Model):
    #user that made the change
    user = models.ForeignKey(ApiKey, on_delete=models.CASCADE)
    #carrier that was changed
    carrier = models.ForeignKey(Carrier, on_delete=models.CASCADE)
    #time of change
    time = models.DateTimeField(auto_now_add=True)
    #type of change
    type = models.CharField(max_length=20)
    #changedBySoftware choose between "edmc" or "discord" or "admin" or "other"
    SOURCE_CHOICES = [
        ('edmc', 'EDMC'),
        ('discord', 'Discord'),
        ('admin', 'Admin'),
        ('other', 'Other'),
    ]
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='other')
    #discorduser
    discorduser = models.CharField(max_length=100, default=None, null=True, blank=True)
    #old value
    oldValue = models.CharField(max_length=100)
    #new value
    newValue = models.CharField(max_length=100)
