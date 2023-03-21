from django.urls import path

from .views import home, editCarrier

urlpatterns = [
    path('', home, name="home"),
    path('editCarrier/<int:carrierID>', editCarrier, name="editCarrier"),
]