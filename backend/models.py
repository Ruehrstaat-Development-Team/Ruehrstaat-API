from django.db import models

from django.contrib.auth.models import AbstractUser

from .managers import AuthManager

from .dataModels import DiscordUserData, FrontierUserData

import uuid


class User(AbstractUser):
    discord_data = models.OneToOneField(
        DiscordUserData, on_delete=models.SET_NULL, null=True, blank=True
    )
    frontier_data = models.ManyToManyField(FrontierUserData, blank=True)

    objects = AuthManager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.EmailField(unique=True, blank=False, null=False)
    USERNAME_FIELD = "username"

    carrier_management_allowed = models.BooleanField(default=False)
