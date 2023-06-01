from django.shortcuts import render

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect

from django.contrib.auth import authenticate, login, logout

from .helpers import (
    get_discord_login_auth_url,
    exchange_discord_login_code,
    get_frontier_auth_url,
    exchange_frontier_code,
)


def discord_login(request: HttpRequest):
    return redirect(get_discord_login_auth_url())


def discord_login_redirect(request: HttpRequest):
    code = request.GET.get("code")
    if not code:
        return redirect("/login?error=No+code+provided")

    user_data = exchange_discord_login_code(code)
    if not user_data:
        return redirect("/login?error=Invalid+code+provided")

    user = authenticate(request, discord_user=user_data)
    if not user:
        # return login_page(request, error="Invalid username or password")
        return redirect("/login?error=Discord+account+unknown")

    login(request, user)
    return redirect("/")


def frontier_login(request: HttpRequest):
    return redirect(get_frontier_auth_url())


def frontier_login_redirect(request: HttpRequest):
    code = request.GET.get("code")
    if not code:
        return redirect("/login?error=No+code+provided")

    user_data = exchange_frontier_code(code)
    if not user_data:
        return redirect("/login?error=Invalid+code+provided")

    user = authenticate(request, frontier_user=user_data)
    if not user:
        # return login_page(request, error="Invalid username or password")
        return redirect("/login?error=Frontier+account+unknown")

    login(request, user)
    return redirect("/")


from .forms import LoginForm


def login_page(request: HttpRequest):
    if request.user.is_authenticated:
        return redirect("/")
    # display login.html page that uses forms.py crispy forms
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            # authenticate user
            user = authenticate(
                request,
                email=form.cleaned_data["email"],
                password=form.cleaned_data["password"],
            )
            if user:
                login(request, user)
                return redirect("/")
            else:
                error = "Invalid email or password"
                return render(request, "backend/login.html", {"form": form})
        else: 
            error = "Invalid email or password"
            return render(request, "backend/login.html", {"form": form})
    else:
        form = LoginForm()
        # check for error in query string
        error = request.GET.get("error")
    return render(request, "backend/login.html", {"form": form, "error": error})


def logout_page(request: HttpRequest):
    logout(request)
    return redirect("/login")


def view_account(request: HttpRequest):
    return render(request, "backend/account.html")

from .forms import ChangeEmailForm
from .models import User
def change_email(request: HttpRequest):
    if request.method == "POST":
        form = ChangeEmailForm(request.POST)
        if form.is_valid():
            if User.objects.filter(email=form.cleaned_data["email"]).exists():
                return redirect("/account/change_email?error=Email+already+in+use")
            # change users email
            user = User.objects.get(id=request.user.id)
            if user is None:
                return redirect("/login?error=Invalid+user")
            user.username = form.cleaned_data["email"]
            user.email = form.cleaned_data["email"]
            user.save()
            # logout user
            logout(request)
            return redirect("/login")
        else: 
            error = "Invalid email"
            return render(request, "backend/change_email.html", {"form": form, "error": error})
    else:
        form = ChangeEmailForm()
        # check for error in query string
        error = request.GET.get("error")
    return render(request, "backend/change_email.html", {"form": form, "error": error})


from .forms import ChangeNameForm
def change_name(request: HttpRequest):
    if request.method == "POST":
        form = ChangeNameForm(request.POST)
        if form.is_valid():
            # change users name
            user = User.objects.get(id=request.user.id)
            if user is None:
                return redirect("/login?error=Invalid+user")
            user.first_name = form.cleaned_data["first_name"]
            user.last_name = form.cleaned_data["last_name"]
            user.save()
            return redirect("/auth/account")
        else: 
            error = "Invalid name"
            return render(request, "backend/change_name.html", {"form": form, "error": error})
    else:
        form = ChangeNameForm()
        # check for error in query string
        error = request.GET.get("error")
    return render(request, "backend/change_name.html", {"form": form, "error": error})

from .helpers import get_discord_link_auth_url, exchange_discord_link_code
def discord_link(request: HttpRequest):
    return redirect(get_discord_link_auth_url())

def discord_link_redirect(request: HttpRequest):
    code = request.GET.get("code")
    if not code:
        return redirect("/auth/account?error=No+code+provided")

    user_data = exchange_discord_link_code(code)
    if not user_data:
        return redirect("/auth/account?error=Invalid+code+provided")

    user = User.objects.get(id=request.user.id)
    if not user:
        return redirect("/login?error=Invalid+user")
    
    # if discord account already linked (saved in User.discord_data Object)
    if user.discord_data is not None:
        return redirect("/auth/account?error=Discord+account+already+linked")
    
    # save discord data to user#
    user = User.objects.addDiscordAccountToUser(user, user_data)

    return redirect("/auth/account")
