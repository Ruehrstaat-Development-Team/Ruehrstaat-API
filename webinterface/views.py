from django.shortcuts import render, redirect
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required

from carriers.models import Carrier, CarrierService

from .forms import EditCarrierForm

@login_required(login_url="/auth/login")
def home(request: HttpRequest):
    # get all carriers owned by the user
    if request.user.is_superuser:
        carriers = Carrier.objects.all()
    else:
        carriers = Carrier.objects.filter(ownerDiscordID=request.user.id)
    return render(request, "webinterface/home.html", {"carriers": carriers})

@login_required(login_url="/auth/login")
def editCarrier(request: HttpRequest, carrierID: int):
    carrier = Carrier.objects.get(id=carrierID)
    if carrier.ownerDiscordID != request.user.id and not request.user.is_superuser:
        return JsonResponse({"error": "You do not own this carrier"}, status=403)
    if request.method == "POST":
        form = EditCarrierForm(request.POST)
        if form.is_valid():
            carrier.name = form.cleaned_data["name"]
            carrier.currentLocation = form.cleaned_data["currentLocation"]
            carrier.previousLocation = form.cleaned_data["previousLocation"]
            carrier.services = form.cleaned_data["services"]
            carrier.dockingAccess = form.cleaned_data["dockingAccess"]
            carrier.imageURL = form.cleaned_data["imageURL"]
            carrier.category = form.cleaned_data["category"]
            carrier.save()
            return redirect("/")
        else:
            return render(request, "webinterface/editCarrier.html", {"carrier": carrier, "form": form})
    else:
        form = EditCarrierForm(initial={
            "name": carrier.name,
            "currentLocation": carrier.currentLocation,
            "previousLocation": carrier.previousLocation,
            "services": carrier.services.all(),
            "dockingAccess": carrier.dockingAccess,
            "imageURL": carrier.imageURL,
            "category": carrier.category,
        })
        return render(request, "webinterface/editCarrier.html", {"carrier": carrier, "form": form})



    


