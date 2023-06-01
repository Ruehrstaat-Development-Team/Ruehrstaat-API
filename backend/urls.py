from django.urls import path

from .views import discord_login, discord_login_redirect, login_page, logout_page
from .views import view_account, change_email, change_name, discord_link, discord_link_redirect

urlpatterns = [
    path("login", login_page, name="login_page"),
    path("login/", login_page, name="login_page"),
    path("logout", logout_page, name="logout_page"),
    path("logout/", logout_page, name="logout_page"),
    path("login/discord", discord_login, name="discord_login"),
    path(
        "login/discord/redirect", discord_login_redirect, name="discord_login_redirect"
    ),
    path("account", view_account, name="view_account"),
    path("account/", view_account, name="view_account"),

    path("account/change_email", change_email, name="change_email"),
    path("account/change_email/", change_email, name="change_email"),
    path("account/change_name", change_name, name="change_name"),
    path("account/change_name/", change_name, name="change_name"),

    path("account/discord/link", discord_link, name="discord_link"),
    path("account/discord/link/", discord_link, name="discord_link"),
    path("account/discord/link/redirect", discord_link_redirect, name="discord_link_redirect"),
    path("account/discord/link/redirect/", discord_link_redirect, name="discord_link_redirect"),
]
