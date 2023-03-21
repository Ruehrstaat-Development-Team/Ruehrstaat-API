from django.shortcuts import render

from django.http import HttpRequest, HttpResponse, JsonResponse

from django.contrib.auth.decorators import login_required

@login_required(login_url="/auth/login")
def home(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"message": "Congrats, you are logged in"})



    


