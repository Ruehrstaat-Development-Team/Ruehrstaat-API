from django.shortcuts import render

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect

from django.contrib.auth import authenticate, login

from .helpers import get_discord_auth_url, exchange_discord_code

def discord_login(request: HttpRequest):
    return redirect(get_discord_auth_url())

def discord_login_redirect(request: HttpRequest):
    code = request.GET.get("code")
    if not code:
        return JsonResponse({"error": "No code provided"}, status=400)
    
    user_data = exchange_discord_code(code)
    if not user_data:
        return JsonResponse({"error": "Invalid code"}, status=400)
    
    user = authenticate(request, user=user_data)
    if not user:
        return JsonResponse({"error": "Invalid user"}, status=400)
    
    login(request, user)
    return redirect("/")


def login_page(request: HttpRequest):
    # display simple page with button that redirects to discord login
    return render(request, "login.html")