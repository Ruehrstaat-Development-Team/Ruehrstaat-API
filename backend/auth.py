from django.contrib.auth.backends import ModelBackend

from .models import User


class DiscordBackend(ModelBackend):
    def authenticate(self, request, discord_user, **kwargs):
        try:
            # look for user in database where user.discord_data.id == user["id"]
            return User.objects.get(discord_data__id=discord_user["id"])
        except User.DoesNotExist:
            # return error message
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class FrontierBackend(ModelBackend):
    def authenticate(self, request, frontier_user, **kwargs):
        try:
            # look for user in database where user.frontier_data.customer_id == user["customer_id"] but frontier_data is a ManyToManyField
            return User.objects.get(
                frontier_data__customer_id=frontier_user["customer_id"]
            )
        except User.DoesNotExist:
            # return error message
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class EmailPasswordBackend(ModelBackend):
    def authenticate(self, request, email, password, **kwargs):
        try:
            # look for user in database where user.email == email
            user = User.objects.get(email=email)
            # check if password is correct
            if user.check_password(password):
                return user
            else:
                return None
        except User.DoesNotExist:
            # return error message
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
