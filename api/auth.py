from rest_framework_api_key.permissions import BaseHasAPIKey, KeyParser

from .models import ApiKey

class BearerKeyParser(KeyParser):
    keyword = "Bearer"

class HasAPIKey(BaseHasAPIKey):
    model = ApiKey  # Or a custom model
    key_parser = BearerKeyParser()

def checkForReadAccessAll(request):
    key = request.META["HTTP_AUTHORIZATION"].split()[1]
    api_key = ApiKey.objects.get_from_key(key)
    return api_key.hasReadAccessTo.all()

def checkForReadAccess(request, carrier_id = None):
    key = request.META["HTTP_AUTHORIZATION"].split()[1]
    api_key = ApiKey.objects.get_from_key(key)
    if api_key.hasReadAccessToAll:
        return True
    if carrier_id and api_key.hasReadAccessTo.filter(id=carrier_id):
        return True
    return False 

def checkForWriteAccessAll(request):
    key = request.META["HTTP_AUTHORIZATION"].split()[1]
    api_key = ApiKey.objects.get_from_key(key)
    return api_key.hasWriteAccessTo.all()

def checkForWriteAccess(request, carrier_id):
    key = request.META["HTTP_AUTHORIZATION"].split()[1]
    api_key = ApiKey.objects.get_from_key(key)
    if api_key.hasWriteAccessToAll:
        return True
    if api_key.hasWriteAccessTo.filter(id=carrier_id):
        return True
    return False 
    