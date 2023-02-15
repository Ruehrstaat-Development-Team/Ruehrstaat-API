from django.shortcuts import render

from carriers.info import getCarrierInfo
from carriers.models import Carrier

from rest_framework import status
from rest_framework.response import Response

def seeCarrier(request, carrier_id):
    #get the carrier info as json data
    carrier = getCarrierInfo(carrier_id)
    if not carrier:
        return render(request, 'embeds/404.html')
    for docking in Carrier.DOCKING_ACCESS_CHOICES:
        if carrier["dockingAccess"] == docking[0]:
            carrier["dockingAccess"] = docking[1]
    for category in Carrier.CARRIER_CATEGORY_CHOICES:
        if carrier["category"] == category[0]:
            carrier["category"] = category[1]

    return render(request, 'embeds/carrier.html', {'carrier': carrier})

    


