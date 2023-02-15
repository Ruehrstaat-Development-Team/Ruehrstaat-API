from .models import Carrier, CarrierService
from api.serializers import CarrierSerializer

# return all carrier information as json
def getCarrierInfo(carrier_id):
    #check if carrier exists with id
    try:
        carrier = Carrier.objects.get(id=carrier_id)
    except Carrier.DoesNotExist:
        return None
    # get all carrier info into json
    serializer = CarrierSerializer(carrier, read_only=True)
    return serializer.data