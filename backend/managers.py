from django.contrib.auth import models

from .dataModels import DiscordUserData, FrontierUserData


class AuthManager(models.UserManager):
    def addDiscordAccountToUser(self, user, raw_discord_data):
        discord_tag = f"{raw_discord_data['username']}#{raw_discord_data['discriminator']}"
        discord_data = DiscordUserData.objects.create(
            id=raw_discord_data["id"],
            username=raw_discord_data["username"],
            discriminator=raw_discord_data["discriminator"],
            discord_tag=discord_tag,
            avatar=raw_discord_data["avatar"],
            locale=raw_discord_data["locale"],
            mfa_enabled=raw_discord_data["mfa_enabled"],
            flags=raw_discord_data["flags"],
            premium_type=raw_discord_data["premium_type"],
            public_flags=raw_discord_data["public_flags"],
        )

        user.discord_data = discord_data
        discord_data.save()
        user.save()
        return user

    def getDiscordUser(self, raw_discord_data):
        try:
            return self.get(discord_data__id=raw_discord_data["id"])
        except self.model.DoesNotExist:
            return None
        
    def removeDiscordAccountFromUser(self, user):
        discord_data = user.discord_data  # Get the discord_data object
        user.discord_data = None  # Remove the reference from the user object
        user.save()  # Save the user object without the reference to discord_data
        discord_data.delete()  # Delete the discord_data object
        return user
    
    def addFrontierAccountToUser(self, user, raw_frontier_data):
        frontier_data = FrontierUserData.objects.create(
            customer_id = raw_frontier_data["customer_id"],
            firstname = raw_frontier_data["firstname"],
            lastname = raw_frontier_data["lastname"],
            email = raw_frontier_data["email"],
            platform = raw_frontier_data["platform"],
        )
        user.frontier_data.add(frontier_data)
        frontier_data.save()
        user.save()
        return user

    def getFrontierUser(self, raw_frontier_data):
        try:
            return self.get(frontier_data__customer_id=raw_frontier_data["customer_id"])
        except self.model.DoesNotExist:
            return None
        
    def removeFrontierAccountFromUser(self, user, frontier_id):
        frontier_data = user.frontier_data.get(customer_id=frontier_id)
        user.frontier_data.remove(frontier_data)
        user.save()
        frontier_data.delete()
        return user

    def create_superuser(self, username, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user
