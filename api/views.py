from django.http import JsonResponse

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from carriers.models import Carrier, CarrierService
from .models import ApiKey, ApiLog
from .auth import HasAPIKey, checkForReadAccessAll, checkForReadAccess, checkForWriteAccessAll, checkForWriteAccess
from .serializers import CarrierSerializer, CarrierServicesSerializer
from .serializers import APIgetCarrierInfoSerializer, APIcarrierJumpSerializer, APIcarrierPermissionSerializer, APIcarrierServiceSerializer
from .serializers import APIcarrierHEADSerializer

from .status_responses import error_400, error_401, error_403, error_404, status_200
from .exceptions import ValidationException

from datetime import datetime
from django.utils import timezone

# get all registered carriers

class getAllCarriers(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        access_carrier_ids = checkForReadAccessAll(request)
        if not access_carrier_ids.count() > 0:
            return error_401(2)
        return JsonResponse({'carriers': CarrierSerializer(Carrier.objects.all().filter(id__in=access_carrier_ids), many=True).data}, safe=False)

class getAllServices(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        access_carrier_ids = checkForReadAccessAll(request)
        print(access_carrier_ids)
        if not access_carrier_ids.count() > 0:
            return error_401(2)
        return JsonResponse({'services': CarrierServicesSerializer(CarrierService.objects.all(), many=True).data}, safe=False)

class getCarrierInfo(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        serializer = APIgetCarrierInfoSerializer(data=request.GET)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationException as e:
            return e.response
        type = serializer.validated_data['type']
        match type:
            case 'docking':
                return JsonResponse({'dockingAccess': Carrier.DOCKING_ACCESS_CHOICES}, safe=False)
            case 'category':
                return JsonResponse({'carrierCategory': Carrier.CARRIER_CATEGORY_CHOICES}, safe=False)

class carrierJump(APIView):
    permission_classes = [HasAPIKey]
    def put(self, request):
        serializer = APIcarrierJumpSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationException as e:
            return e.response
        carrier_id = serializer.validated_data['id']
        request_type = serializer.validated_data['type']
        request_source = serializer.validated_data['source']
        carrier = Carrier.objects.get(id=carrier_id)
        body = serializer.validated_data['body']

        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)

        match request_type:
            case 'jump':
                carrier.previousLocation = carrier.currentLocation
                carrier.currentLocation = body
                carrier.save()
                ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='jump', oldValue=carrier.previousLocation, newValue=carrier.currentLocation)
                return status_200('Carrier jump noted')
            case 'cancel':
                if carrier.previousLocation == None:
                    return error_400(8)
                oldValue=carrier.previousLocation
                carrier.currentLocation = carrier.previousLocation
                carrier.previousLocation = None
                carrier.save()
                ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='jumpcancel', oldValue=oldValue, newValue=carrier.currentLocation)
                return status_200('Carrier jump cancelled')
            case _:
                return error_400(5)

class carrierPermission(APIView):
    permission_classes = [HasAPIKey]
    def put(self, request):
        serializer = APIcarrierPermissionSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationException as e:
            return e.response
        carrier_id = serializer.validated_data['id']
        request_source = serializer.validated_data['source']
        request_discord_id = serializer.validated_data['discord_id']
        new_access = serializer.validated_data['access']
        allowNotorious = bool(serializer.validated_data['notorious'])

        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)

        ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='permission', oldValue=carrier.dockingAccess, newValue=new_access, discorduser=request_discord_id)
        carrier.dockingAccess = new_access
        carrier.allowNotorious = allowNotorious
        carrier.save()
        return status_200('Carrier permission updated')


class carrierService(APIView):
    permission_classes = [HasAPIKey]
    def put(self, request):
        serializer = APIcarrierServiceSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationException as e:
            return e.response
        
        carrier_id = serializer.validated_data['id']
        operation = serializer.validated_data['operation'].lower()
        serviceName = serializer.validated_data['service']
        source = serializer.validated_data['source']
        request_discord_id = serializer.validated_data['discord_id']

        carrier = Carrier.objects.get(id=carrier_id)
        service = CarrierService.objects.get(name=serviceName)

        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)

        if operation == 'activate' or operation == 'resume':
            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=source, type='service-activate', oldValue=carrier.services, newValue=service, discorduser=request_discord_id)
            carrier.services.add(service)
            carrier.save()
            return status_200('Service activated')
        elif operation == 'deactivate' or operation == 'pause':
            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=source, type='service-deactivate', oldValue=carrier.services, newValue=service, discorduser=request_discord_id)
            carrier.services.remove(service)
            carrier.save()
            return status_200('Service deactivated')
        else:
            return error_404(3)
        



class carrier(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        carrier_id = request.GET.get('id')
        carrier_callsign = request.GET.get('callsign')
        if not carrier_id and not carrier_callsign:
            return error_400(2)
        if not Carrier.objects.filter(id=carrier_id) and not Carrier.objects.filter(callsign=carrier_callsign):
            return error_404(1)
        carrier = Carrier.objects.get(id=carrier_id)
        if not carrier:
            carrier = Carrier.objects.get(callsign=carrier_callsign)
            carrier_id = carrier.id
        if not checkForReadAccess(request, carrier_id):
            return error_401(1)
        serializer = CarrierSerializer(carrier)
        return JsonResponse({'carrier': serializer.data}, safe=False)

    def put(self, request):
        carrier_id = request.data.get('id')
        request_source = "other"
        if request.data.get('source'):
            request_source = request.data.get('source')

        request_discord_id = None
        if request.data.get('discord_id'):
            request_discord_id = request.data.get('discord_id')
        if not carrier_id:
            return error_400(1)
        if not Carrier.objects.filter(id=carrier_id):
            return error_400(3)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)

        editsMade = False
        changes = {}
        old_values = {}

        if request.data.get('name'):
            old_values['name'] = carrier.name
            carrier.name = request.data.get('name')
            changes['name'] = request.data.get('name')
            editsMade = True
        if request.data.get('callsign'):
            old_values['callsign'] = carrier.callsign   
            carrier.callsign = request.data.get('callsign')
            changes['callsign'] = request.data.get('callsign')
            editsMade = True
        if request.data.get('currentLocation'):
            old_values['currentLocation'] = carrier.currentLocation
            carrier.currentLocation = request.data.get('currentLocation')
            changes['currentLocation'] = request.data.get('currentLocation')
            editsMade = True
        if request.data.get('previousLocation'):
            old_values['previousLocation'] = carrier.previousLocation
            carrier.previousLocation = request.data.get('previousLocation')
            changes['previousLocation'] = request.data.get('previousLocation')
            editsMade = True
        if request.data.get('dockingAccess'):
            old_values['dockingAccess'] = carrier.dockingAccess
            carrier.dockingAccess = request.data.get('dockingAccess')
            changes['dockingAccess'] = request.data.get('dockingAccess')
            editsMade = True
        if request.data.get('notorious'):
            old_values['notorious'] = carrier.allowNotorious
            carrier.allowNotorious = bool(request.data.get('notorious'))
            changes['allowNotorious'] = bool(request.data.get('notorious'))
            editsMade = True
        if request.data.get('fuel'):
            old_values['fuel'] = carrier.fuelLevel
            carrier.fuelLevel = request.data.get('fuel')
            changes['fuelLevel'] = request.data.get('fuel')
            editsMade = True
        if request.data.get('cargoUsed'):
            old_values['cargoUsedSpace'] = carrier.cargoUsedSpace
            carrier.cargoUsedSpace = request.data.get('cargoUsed')
            changes['cargoUsedSpace'] = request.data.get('cargoUsed')
            editsMade = True
        if request.data.get('cargoFree'):
            old_values['cargoFreeSpace'] = carrier.cargoFreeSpace
            carrier.cargoFreeSpace = request.data.get('cargoFree')
            changes['cargoFreeSpace'] = request.data.get('cargoFree')
            editsMade = True
        if request.data.get('balance'):
            old_values['balance'] = carrier.balance
            carrier.balance = request.data.get('balance')
            changes['balance'] = request.data.get('balance')
            editsMade = True
        if request.data.get('reserveBalance'):
            old_values['reserveBalance'] = carrier.reserveBalance
            carrier.reserveBalance = request.data.get('reserveBalance')
            changes['reserveBalance'] = request.data.get('reserveBalance')
            editsMade = True
        if request.data.get('availableBalance'):
            old_values['availableBalance'] = carrier.availableBalance
            carrier.availableBalance = request.data.get('availableBalance')
            changes['availableBalance'] = request.data.get('availableBalance')
            editsMade = True
        if request.data.get('owner'):
            old_values['owner'] = carrier.owner
            carrier.owner = request.data.get('owner')
            changes['owner'] = request.data.get('owner')
            editsMade = True
        if request.data.get('ownerDiscordID'):
            old_values['ownerDiscordID'] = carrier.ownerDiscordID
            carrier.ownerDiscordID = request.data.get('ownerDiscordID')
            changes['ownerDiscordID'] = request.data.get('ownerDiscordID')
            editsMade = True
        if request.data.get('imageURL'):
            old_values['imageURL'] = carrier.imageURL
            carrier.imageURL = request.data.get('imageURL')
            changes['imageURL'] = request.data.get('imageURL')
            editsMade = True
        if request.data.get('category'):
            old_values['category'] = carrier.category
            carrier.category = request.data.get('category')
            changes['category'] = request.data.get('category')
            editsMade = True

        if editsMade:
            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='carrier-update', oldValue=old_values, newValue=changes, discorduser=request_discord_id)

            carrier.save()
            serializer = CarrierSerializer(carrier)

        return Response({'carrier': serializer.data}, status=status.HTTP_200_OK)
            

    def post(self, request):
        if request.data.get('id'):
            return error_400(11)
        if not checkForWriteAccess(request, None):
            return error_401(3)
        serializer = CarrierSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'carrier': serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        carrier_id = request.GET.get('id')
        request_source = "other"
        if request.GET.get('source'):
            request_source = request.GET.get('source')
        if not carrier_id:
            return error_400(1)
        if not Carrier.objects.filter(id=carrier_id):
            return error_404(1)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)
        ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='carrier-delete', oldValue=carrier, newValue=None)
        carrier.delete()
        return Response({'success': 'carrier successfully deleted'}, status=status.HTTP_204_NO_CONTENT)
    
    # HEAD request to check if carrier has been modified since last request (for caching)
    def head(self, request):
        serializer = APIcarrierHEADSerializer(data=request.GET)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationException as e:
            return e.response
        
        carrier_id = serializer.validated_data['id']
        timestamp = serializer.validated_data['timestamp']
        source = serializer.validated_data['source']

        # try to convert timestamp to int
        try:
            timestamp = timezone.make_aware(datetime.fromtimestamp(int(timestamp)), timezone.get_current_timezone())
        except ValueError:
            # check if timestamp is maybe a string in iso format
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                return error_400(15)

        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForReadAccess(request, carrier_id):
            return error_401(1)
        
        ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=source, type='carrier-head', oldValue=None, newValue=None)

        # check if carrier has been modified since last request
        if carrier.date_modified > timestamp:
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_304_NOT_MODIFIED)
        


