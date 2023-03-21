from django.contrib.auth import models

class DiscordUserAuthManager(models.UserManager):
    def create_discord_user(self, user):
        discord_tag = f"{user['username']}#{user['discriminator']}"
        return self.create(
            id=user["id"],
            username=user['username'],
            discord_tag=discord_tag,
            avatar=user["avatar"],
            locale=user["locale"],
            mfa_enabled=user["mfa_enabled"],
            flags=user["flags"],
            premium_type=user["premium_type"],
            public_flags=user["public_flags"],
        )

