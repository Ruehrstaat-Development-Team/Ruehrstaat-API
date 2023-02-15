from django.http import JsonResponse

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from carriers.models import Carrier, CarrierService
from .models import ApiKey, ApiLog
from .auth import HasAPIKey, checkForReadAccessAll, checkForReadAccess, checkForWriteAccessAll, checkForWriteAccess
from .serializers import CarrierSerializer, CarrierServicesSerializer

# get all registered carriers

class getAllCarriers(APIView):

    permission_classes = [HasAPIKey]
    # get all carriers
    def get(self, request):
        access_carrier_ids = checkForReadAccessAll(request)
        carriers = Carrier.objects.all()
        # create a list of carriers that are allowed to be accessed
        if access_carrier_ids:
            carriers = carriers.filter(id__in=access_carrier_ids)
        serializer = CarrierSerializer(carriers, many=True)
        return JsonResponse({'carriers': serializer.data}, safe=False)

class getAllServices(APIView):
    permission_classes = [HasAPIKey]

    def get(self, request):
        if checkForReadAccessAll(request):
            return Response({'error': 'No read access'}, status=status.HTTP_401_UNAUTHORIZED)
        services = CarrierService.objects.all()
        serializer = CarrierServicesSerializer(services, many=True)
        return JsonResponse({'services': serializer.data}, safe=False)

class getCarrierInfo(APIView):
    permission_classes = [HasAPIKey]

    def get(self, request):
        type = request.GET.get('type')
        if not type:
            return Response({'error': 'No type provided'}, status=status.HTTP_400_BAD_REQUEST)
        if type == 'docking':
            # get DOCKING_ACCESS_CHOICES from carrier model
            return JsonResponse({'dockingAccess': Carrier.DOCKING_ACCESS_CHOICES}, safe=False)
        elif type == 'category':
            # get CARRIER_CATEGORY_CHOICES from carrier model
            return JsonResponse({'carrierCategory': Carrier.CARRIER_CATEGORY_CHOICES}, safe=False)
        else:
            return Response({'error': 'Invalid type provided'}, status=status.HTTP_400_BAD_REQUEST)

class carrierJump(APIView):
    permission_classes = [HasAPIKey]

    def put(self, request):
        carrier_id = request.data.get('id')
        request_type = request.data.get('type')
        request_source = "other"
        if request.data.get('source'):
            request_source = request.data.get('source')

        if not carrier_id:
            return Response({'error': 'No carrier id provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not request_type:
            return Response({'error': 'No request type provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not Carrier.objects.filter(id=carrier_id):
            return Response({'error': 'Invalid carrier id provided'}, status=status.HTTP_404_NOT_FOUND)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return Response({'error': 'Carrier not allowed'}, status=status.HTTP_401_UNAUTHORIZED)
        if request_type == 'jump':
            # get request json data
            body = request.data.get('body')

            if not body:
                return Response({'error': 'No body provided'}, status=status.HTTP_400_BAD_REQUEST)

            carrier.previousLocation = carrier.currentLocation
            carrier.currentLocation = body

            carrier.save()
            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='jump', oldValue=carrier.previousLocation, newValue=carrier.currentLocation)

            return Response({'success': 'Carrier jump noted'}, status=status.HTTP_200_OK)

        elif request_type == 'cancel':
            carrier.currentLocation = carrier.previousLocation
            carrier.previousLocation = None

            carrier.save()
            ApiLog.objects.create(key=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='jumpcancel', oldValue=carrier.currentLocation, newValue=carrier.previousLocation)

            return Response({'success': 'Carrier jump cancelled'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid request type provided'}, status=status.HTTP_400_BAD_REQUEST)

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
            return Response({'error': 'No carrier id provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not Carrier.objects.filter(id=carrier_id):
            return Response({'error': 'Invalid carrier id provided'}, status=status.HTTP_400_BAD_REQUEST)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return Response({'error': 'Carrier not allowed'}, status=status.HTTP_401_UNAUTHORIZED)
        
        new_access = request.data.get('access')

        ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='permission', oldValue=carrier.dockingAccess, newValue=new_access, discorduser=request_discord_id)

        carrier.dockingAccess = new_access
        carrier.save()
        
        return Response({'success': 'Carrier permission updated'}, status=status.HTTP_200_OK)


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
            return Response({'error': 'No carrier id provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not operation:
            return Response({'error': 'No operation provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not serviceName:
            return Response({'error': 'No service provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not Carrier.objects.filter(id=carrier_id):
            return Response({'error': 'Invalid carrier id provided'}, status=status.HTTP_404_NOT_FOUND)
        if not CarrierService.objects.filter(name=serviceName):
            return Response({'error': 'Invalid service provided'}, status=status.HTTP_404_NOT_FOUND)
        carrier = Carrier.objects.get(id=carrier_id)
        service = CarrierService.objects.get(name=serviceName)
        if not checkForWriteAccess(request, carrier_id):
            return Response({'error': 'Carrier not allowed'}, status=status.HTTP_401_UNAUTHORIZED)
        if operation == 'activate' or operation == 'resume':

            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=source, type='service-activate', oldValue=carrier.services, newValue=service, discorduser=request_discord_id)

            carrier.services.add(service)
            carrier.save()
            return Response({'success': 'Service activated'}, status=status.HTTP_200_OK)
        elif operation == 'deactivate' or operation == 'pause':

            ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=source, type='service-deactivate', oldValue=carrier.services, newValue=service, discorduser=request_discord_id)

            carrier.services.remove(service)
            carrier.save()
            return Response({'success': 'Service deactivated'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid operation provided'}, status=status.HTTP_404_NOT_FOUND)
        



class carrier(APIView):

    permission_classes = [HasAPIKey]

    def get(self, request):
        carrier_id = request.GET.get('id')
        carrier_callsign = request.GET.get('callsign')
        if not carrier_id and not carrier_callsign:
            return Response({'error': 'No carrier id or callsign provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not Carrier.objects.filter(id=carrier_id) and not Carrier.objects.filter(callsign=carrier_callsign):
            return Response({'error': 'Invalid carrier id provided'}, status=status.HTTP_404_NOT_FOUND)
        carrier = Carrier.objects.get(id=carrier_id)
        if not carrier:
            carrier = Carrier.objects.get(callsign=carrier_callsign)
            carrier_id = carrier.id
        if not checkForReadAccess(request, carrier_id):
            return Response({'error': 'Carrier not allowed'}, status=status.HTTP_401_UNAUTHORIZED)
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
                return Response({'error': 'Invalid carrier id provided, to create a carrier please use POST request'}, status=status.HTTP_400_BAD_REQUEST)
            carrier = Carrier.objects.get(id=carrier_id)
            # check for access to carrier
            if not checkForWriteAccess(request, carrier_id):
                return Response({'error': 'Carrier not allowed'}, status=status.HTTP_401_UNAUTHORIZED)

            changes = {}
            old_values = {}

            # update carrier with new values from post form, if fields empty use old values
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
            return Response({'error': 'No carrier id provided'}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        if request.data.get('id'):
            return Response({'error': 'Use PUT request to edit carrier'}, status=status.HTTP_400_BAD_REQUEST)
        if not checkForWriteAccess(request, None):
            return Response({'error': 'Not allowed to create new carriers'}, status=status.HTTP_401_UNAUTHORIZED)
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
            return Response({'error': 'No carrier id provided'}, status=status.HTTP_400_BAD_REQUEST)
        if not Carrier.objects.filter(id=carrier_id):
            return Response({'error': 'Invalid carrier id provided'}, status=status.HTTP_404_NOT_FOUND)
        carrier = Carrier.objects.get(id=carrier_id)
        if not checkForWriteAccess(request, carrier_id):
            return Response({'error': 'Carrier not allowed'}, status=status.HTTP_401_UNAUTHORIZED)

        ApiLog.objects.create(user=ApiKey.objects.get_from_key(request.META["HTTP_AUTHORIZATION"].split()[1]), carrier=carrier, source=request_source, type='carrier-delete', oldValue=carrier, newValue=None)
        
        carrier.delete()
        return Response({'success': 'carrier successfully deleted'}, status=status.HTTP_204_NO_CONTENT)
            

                
                




