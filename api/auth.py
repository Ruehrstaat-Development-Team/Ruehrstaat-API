from rest_framework_api_key.permissions import BaseHasAPIKey, KeyParser

from .models import ApiKey

from carriers.models import Carrier

class BearerKeyParser(KeyParser):
    keyword = "Bearer"

class HasAPIKey(BaseHasAPIKey):
    model = ApiKey 
    key_parser = BearerKeyParser()

class HasReadAccess(HasAPIKey):
    def has_permission(self, request, view):
        if super().has_permission(request, view):
            return checkForReadAccess(request)
        return False
    
    def has_object_permission(self, request, view, obj):
        if super().has_object_permission(request, view, obj):
            return checkForReadAccess(request, obj.id)
        return False
    
class HasWriteAccess(HasAPIKey):
    def has_permission(self, request, view):
        if super().has_permission(request, view):
            return checkForWriteAccess(request)
        return False
    
    def has_object_permission(self, request, view, obj):
        if super().has_object_permission(request, view, obj):
            return checkForWriteAccess(request, obj.id)
        return False

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

def checkForWriteAccess(request, carrier_id = None):
    api_key = ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1])
    if api_key.hasWriteAccessToAll or ( carrier_id and api_key.hasWriteAccessTo.filter(id=carrier_id) ):
        return True
    return False 
    