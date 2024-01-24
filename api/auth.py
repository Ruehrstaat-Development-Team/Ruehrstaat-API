from rest_framework_api_key.permissions import BaseHasAPIKey, KeyParser

from .models import ApiKey

from carriers.models import Carrier

class BearerKeyParser(KeyParser):
    keyword = "Bearer"

class HasAPIKey(BaseHasAPIKey):
    model = ApiKey 
    key_parser = BearerKeyParser()

def checkForReadAccessAll(request):
    api_key = ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1])
    if api_key.hasReadAccessToAll:
        return Carrier.objects.all()
    return api_key.hasReadAccessTo.all()

def checkForReadAccess(request, carrier_id = None):
    api_key = ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1])
    if api_key.hasReadAccessToAll or ( carrier_id and api_key.hasReadAccessTo.filter(id=carrier_id) ):
        return True
    return False 

def checkForWriteAccessAll(request):
    api_key = ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1])
    if api_key.hasWriteAccessToAll:
        return Carrier.objects.all()
    return api_key.hasWriteAccessTo.all()

def checkForWriteAccess(request, carrier_id):
    api_key = ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1])
    if api_key.hasWriteAccessToAll or ( carrier_id and api_key.hasWriteAccessTo.filter(id=carrier_id) ):
        return True
    return False 
    