from django.urls import path

from .views import home, editCarrier, seeCarrier

urlpatterns = [
    path('', home, name="home"),
    path('editCarrier/<int:carrierID>', editCarrier, name="editCarrier"),
    path('seeCarrier/<int:carrierID>', seeCarrier, name="seeCarrier"),
]