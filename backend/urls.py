from django.urls import path

from .views import discord_login, discord_login_redirect

urlpatterns = [
    path('login', discord_login, name="discord_login"),
    path('login/', discord_login, name="discord_login"),
    path('login/redirect', discord_login_redirect, name="discord_login_redirect"),
]