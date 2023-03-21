from django.contrib.auth.backends import ModelBackend

from .models import User

class DiscordBackend(ModelBackend):
    def authenticate(self, request, user, **kwargs):
        try:
            return User.objects.get(id=user["id"])
        except User.DoesNotExist:
            return User.objects.create_discord_user(user)

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None