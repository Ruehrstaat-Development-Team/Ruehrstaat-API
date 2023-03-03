from django.http import JsonResponse

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from carriers.models import Carrier, CarrierService
from .models import ApiKey, ApiLog
from .auth import HasAPIKey, checkForReadAccessAll, checkForReadAccess, checkForWriteAccessAll, checkForWriteAccess
from .serializers import CarrierSerializer, CarrierServicesSerializer

from .status_responses import error_400, error_401, error_403, error_404, status_200

# get all registered carriers

class getAllCarriers(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        access_carrier_ids = checkForReadAccessAll(request)
        if not access_carrier_ids:
            return error_401(2)
        return JsonResponse({'carriers': CarrierSerializer(Carrier.objects.all().filter(id__in=access_carrier_ids), many=True).data}, safe=False)

class getAllServices(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        if checkForReadAccessAll(request):
            return error_401(2)
        return JsonResponse({'services': CarrierServicesSerializer(CarrierService.objects.all(), many=True).data}, safe=False)

class getCarrierInfo(APIView):
    permission_classes = [HasAPIKey]
    def get(self, request):
        type = request.GET.get('type')
        if not type:
            return error_400(4)
        match type:
            case 'docking':
                return JsonResponse({'dockingAccess': Carrier.DOCKING_ACCESS_CHOICES}, safe=False)
            case 'category':
                return JsonResponse({'carrierCategory': Carrier.CARRIER_CATEGORY_CHOICES}, safe=False)
            case _:
                return error_400(5)

class carrierJump(APIView):
    permission_classes = [HasAPIKey]
    def put(self, request):
        carrier_id = request.data.get('id')
        request_type = request.data.get('type')
        request_source = "other"
        if request.data.get('source'):
            request_source = request.data.get('source')

        if not carrier_id:
            return error_400(1)
        if not request_type:
            return error_400(4)
        if not Carrier.objects.filter(id=carrier_id):
            return error_404(1)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)
        match request_type:
            case 'jump':
                body = request.data.get('body')
                if not body:
                    return error_400(6)
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
            return error_404(1)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return error_401(1)

        new_access = request.data.get('access')
        if not new_access:
            return error_400(7)

        ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='permission', oldValue=carrier.dockingAccess, newValue=new_access, discorduser=request_discord_id)
        carrier.dockingAccess = new_access
        carrier.save()
        return status_200('Carrier permission updated')


class carrierService(APIView):
    permission_classes = [HasAPIKey]
    def put(self, request):
        carrier_id = request.data.get('id')
        operation = request.data.get('operation').lower()
        serviceName = request.data.get('service')
        source = "other"
        if request.data.get('source'):
            source = request.data.get('source')
        request_discord_id = None
        if request.data.get('discord_id'):
            request_discord_id = request.data.get('discord_id')

        if not carrier_id:
            return error_400(1)
        if not operation:
            return error_400(9)
        if not serviceName:
            return error_400(10)
        if not Carrier.objects.filter(id=carrier_id):
            return error_404(1)
        if not CarrierService.objects.filter(name=serviceName):
            return error_404(2)
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
        if carrier_id:
            if not Carrier.objects.filter(id=carrier_id):
                return error_400(3)
            carrier = Carrier.objects.get(id=carrier_id)
            if not checkForWriteAccess(request, carrier_id):
                return error_401(1)

            changes = {}
            old_values = {}

            if request.data.get('name'):
                old_values['name'] = carrier.name
                carrier.name = request.data.get('name')
                changes['name'] = request.data.get('name')
            if request.data.get('callsign'):
                old_values['callsign'] = carrier.callsign   
                carrier.callsign = request.data.get('callsign')
                changes['callsign'] = request.data.get('callsign')
            if request.data.get('currentLocation'):
                old_values['currentLocation'] = carrier.currentLocation
                carrier.currentLocation = request.data.get('currentLocation')
                changes['currentLocation'] = request.data.get('currentLocation')
            if request.data.get('previousLocation'):
                old_values['previousLocation'] = carrier.previousLocation
                carrier.previousLocation = request.data.get('previousLocation')
                changes['previousLocation'] = request.data.get('previousLocation')
            if request.data.get('dockingAccess'):
                old_values['dockingAccess'] = carrier.dockingAccess
                carrier.dockingAccess = request.data.get('dockingAccess')
                changes['dockingAccess'] = request.data.get('dockingAccess')
            if request.data.get('owner'):
                old_values['owner'] = carrier.owner
                carrier.owner = request.data.get('owner')
                changes['owner'] = request.data.get('owner')
            if request.data.get('ownerDiscordID'):
                old_values['ownerDiscordID'] = carrier.ownerDiscordID
                carrier.ownerDiscordID = request.data.get('ownerDiscordID')
                changes['ownerDiscordID'] = request.data.get('ownerDiscordID')
            if request.data.get('imageURL'):
                old_values['imageURL'] = carrier.imageURL
                carrier.imageURL = request.data.get('imageURL')
                changes['imageURL'] = request.data.get('imageURL')
            if request.data.get('category'):
                old_values['category'] = carrier.category
                carrier.category = request.data.get('category')
                changes['category'] = request.data.get('category')

            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='carrier-update', oldValue=old_values, newValue=changes, discorduser=request_discord_id)

            carrier.save()
            serializer = CarrierSerializer(carrier)

            return Response({'carrier': serializer.data}, status=status.HTTP_200_OK)
        else:
            return error_400(1)

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
            

                
                




