# api/admin.py
from django.contrib import admin
from rest_framework_api_key.admin import APIKeyModelAdmin
from .models import ApiKey, ApiLog

@admin.register(ApiKey)
class ApiAPIKeyModelAdmin(APIKeyModelAdmin):
    pass

@admin.register(ApiLog)
class ApiLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'carrier', 'time', 'type', 'source', 'oldValue', 'newValue')
    list_filter = ('user', 'carrier', 'time', 'type', 'source', 'oldValue', 'newValue')
    search_fields = ('user', 'carrier', 'time', 'type', 'source', 'oldValue', 'newValue')
    ordering = ('-time',)


