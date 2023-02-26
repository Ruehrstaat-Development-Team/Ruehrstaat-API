from django.urls import path

from . import views
from .views import seeCarrier

urlpatterns = [
    path('seeCarrier/<int:carrier_id>', seeCarrier, name="seeCarrier"),
]