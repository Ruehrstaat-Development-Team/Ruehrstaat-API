from django.contrib import admin
from .models import Carrier, CarrierService

# Register your models here.

admin.site.register(CarrierService)
admin.site.register(Carrier)
