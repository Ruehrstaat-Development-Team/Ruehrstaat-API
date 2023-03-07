from rest_framework import serializers

from carriers.models import Carrier
from carriers.models import CarrierService

class CarrierServicesSerializer(serializers.ModelSerializer):
    class Meta:
        model = CarrierService
        fields = ('name', 'label', 'description', 'odyssey')

class CarrierSerializer(serializers.ModelSerializer):
    services = CarrierServicesSerializer(many=True, read_only=True)
    class Meta:
        model = Carrier
        fields = ['id', 'name', 'callsign', 'currentLocation', 'previousLocation', 'dockingAccess', 'services', 'owner', 'ownerDiscordID', 'imageURL', 'category']

from .exceptions import Validation400Exception, Validation401Exception, Validation403Exception, Validation404Exception

class APISerializer():
    values = {}
    def __init__(self, data):
        self.data = data.copy()
        self.validated_data = {}

    def validate(self):
        assert isinstance(self.data, dict), 'Data must be a dictionary'
        
        for key, value in self.values.items():
            if key not in self.data:
                if value["required"]["value"]:
                    # see if condition is met
                    if "conditions" in value:
                        continueloop = False
                        for conditionKey, conditionValue in value["conditions"]["value"].items():
                            if not self.data[conditionKey] == conditionValue:
                                self.data[key] = None
                                continueloop = True
                                break
                        if continueloop:
                            continue
                    raise Validation400Exception(value["required"]["errorNumber"])
                else:
                    if "default" in value:
                        self.data[key] = value["default"]
                continue
            if not isinstance(self.data[key], value["class"]):
                # check if conversion to target class is possible
                try:
                    self.data[key] = value["class"](self.data[key])
                except:
                    raise Validation400Exception(value["required"]["errorNumber"])
            if "choices" in value:
                if self.data[key] not in value["choices"]["value"]:
                    raise Validation400Exception(value["choices"]["errorNumber"])
            if "conditions" in value:
                for conditionKey, conditionValue in value["conditions"]["value"].items():
                    if self.data[conditionKey] != conditionValue:
                        raise Validation400Exception(value["conditions"]["errorNumber"])
            if "object" in value:
                validation = False
                if value["object"]["field"] == "id":
                    validation = value["object"]["value"].objects.filter(id=self.data[key]).exists()
                if value["object"]["field"] == "name":
                    validation = value["object"]["value"].objects.filter(name=self.data[key]).exists()
                if not validation:
                    raise Validation404Exception(value["object"]["errorNumber"])
    def is_valid(self, raise_exception=False):
        try:
            self.validate()
            self.validated_data = self.data
            return True
        except Validation400Exception as e:
            if raise_exception:
                raise e
            return False

class APIgetCarrierInfoSerializer(APISerializer):
    values = {
        "type": {"class": str, "required": {"value": True, "errorNumber": 4}, "choices": {"value": ["category", "docking"], "errorNumber": 5}}
    }

class APIcarrierJumpSerializer(APISerializer):
    values = {
        "id": {"class": str, "required": {"value": True, "errorNumber": 1}, "object": {"value": Carrier, "errorNumber": 1, "field": "id"}},
        "type": {"class": str, "required": {"value": True, "errorNumber": 4}, "choices": {"value": ["jump", "cancel"], "errorNumber": 5}},
        "source": {"class": str, "required": {"value": False}, "default": "other"},
        "body": {"class": str, "required": {"value": True, "errorNumber": 6}, "conditions": {"value": {"type": "jump"}, "errorNumber": 6}},
    }

class APIcarrierPermissionSerializer(APISerializer):
    values = {
        "id": {"class": str, "required": {"value": True, "errorNumber": 1}, "object": {"value": Carrier, "errorNumber": 1, "field": "id"}},
        "access": {"class": str, "required": {"value": True, "errorNumber": 7}, "choices": {"value": [x[0] for x in Carrier.DOCKING_ACCESS_CHOICES], "errorNumber": 12}},
        "source": {"class": str, "required": {"value": False}, "default": "other"},
        "discord_id": {"class": str, "required": {"value": False}, "default": None},
    }

class APIcarrierServiceSerializer(APISerializer):
    values = {
        "id": {"class": str, "required": {"value": True, "errorNumber": 1}, "object": {"value": Carrier, "errorNumber": 1, "field": "id"}},
        "operation": {"class": str, "required": {"value": True, "errorNumber": 9}, "choices": {"value": ["activate", "resume", "deactivate", "pause"], "errorNumber": 13}},
        "service": {"class": str, "required": {"value": True, "errorNumber": 10}, "object": {"value": CarrierService, "errorNumber": 2, "field": "name"}},
        "source": {"class": str, "required": {"value": False}, "default": "other"},
        "discord_id": {"class": str, "required": {"value": False}, "default": None},
    }


    


                
        
        
    
    
