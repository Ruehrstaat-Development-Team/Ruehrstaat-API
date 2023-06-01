from django.conf import settings
from urllib import parse as urllib_parse

from requests import post as requests_post, get as requests_get


def get_discord_login_auth_url():
    client_id = settings.DISCORD_CLIENT_ID
    redirect_url = urllib_parse.quote(get_discord_login_redirect_url(), safe="")
    return f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_url}&response_type=code&scope=identify"


def get_discord_login_redirect_url():
    if settings.DEBUG:
        redirect_url = "http://127.0.0.1:8000/auth/login/discord/redirect"
    else:
        redirect_url = "https://api.ruehrstaat.de/auth/login/discord/redirect"
    return redirect_url


def exchange_discord_login_code(code: str):
    data = {
        "client_id": settings.DISCORD_CLIENT_ID,
        "client_secret": settings.DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": get_discord_login_redirect_url(),
        "scope": "identify",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    credentials = requests_post(
        "https://discord.com/api/oauth2/token", data=data, headers=headers
    ).json()
    access_token = credentials.get("access_token")
    if not access_token:
        return None
    user = requests_get(
        "https://discord.com/api/v6/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()
    return user

def get_discord_link_auth_url():
    client_id = settings.DISCORD_CLIENT_ID
    redirect_url = urllib_parse.quote(get_discord_link_redirect_url(), safe="")
    return f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_url}&response_type=code&scope=identify"


def get_discord_link_redirect_url():
    if settings.DEBUG:
        redirect_url = "http://127.0.0.1:8000/auth/account/discord/link/redirect"
    else:
        redirect_url = "https://api.ruehrstaat.de/auth/account/discord/link/redirect"
    return redirect_url


def exchange_discord_link_code(code: str):
    data = {
        "client_id": settings.DISCORD_CLIENT_ID,
        "client_secret": settings.DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": get_discord_link_redirect_url(),
        "scope": "identify",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    credentials = requests_post(
        "https://discord.com/api/oauth2/token", data=data, headers=headers
    ).json()
    access_token = credentials.get("access_token")
    if not access_token:
        return None
    user = requests_get(
        "https://discord.com/api/v6/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()
    return user


def get_frontier_auth_url():
    client_id = settings.FRONTIER_CLIENT_ID
    redirect_url = urllib_parse.quote(get_frontier_redirect_url(), safe="")
    return f"https://frontier.orbit.sh/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_url}&response_type=code&scope=identify"


def get_frontier_redirect_url():
    if settings.DEBUG:
        redirect_url = "http://127.0.0.1:8000/auth/login/frontier/redirect"
    else:
        redirect_url = "https://api.ruehrstaat.de/auth/login/frontier/redirect"
    return redirect_url


def exchange_frontier_code(code: str):
    data = {
        "client_id": settings.FRONTIER_CLIENT_ID,
        "client_secret": settings.FRONTIER_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": get_frontier_redirect_url(),
        "scope": "identify",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    credentials = requests_post(
        "https://frontier.orbit.sh/api/oauth2/token", data=data, headers=headers
    ).json()
    access_token = credentials.get("access_token")
    if not access_token:
        return None
    user = requests_get(
        "https://frontier.orbit.sh/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()
    return user
