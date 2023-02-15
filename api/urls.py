from django.urls import path

from . import views

urlpatterns = [
    path('getAllCarriers', views.getAllCarriers.as_view(), name='getAllCarriers'),
    path('carrier', views.carrier.as_view(), name='carrier'),
    path('carrierJump', views.carrierJump.as_view(), name='carrierJump'),
    path('carrierPermission', views.carrierPermission.as_view(), name='carrierPermission'),
    path('carrierService', views.carrierService.as_view(), name='carrierService'),
    path('getAllServices', views.getAllServices().as_view(), name='getAllServices'),
    path('getCarrierInfo', views.getCarrierInfo().as_view(), name='getCarrierInfo'),
]