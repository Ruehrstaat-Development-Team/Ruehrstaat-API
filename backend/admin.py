from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm as BaseUserChangeForm

from .models import User
from .dataModels import DiscordUserData, FrontierUserData

admin.site.register(DiscordUserData)
admin.site.register(FrontierUserData)

# Register your models here.
class UserChangeForm(BaseUserChangeForm):
    class Meta(BaseUserChangeForm.Meta):
        model = User
        fields = "__all__"

class UserAdmin(BaseUserAdmin):
    ordering = ("id",)  # Update the ordering attribute
    list_display = ("id", "username", "is_staff", "is_superuser")
    form = UserChangeForm
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Personal info", {"fields": ("email", "first_name", "last_name")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions", "carrier_management_allowed")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
        ("Discord", {"fields": ("discord_data",)}),
        ("Frontier", {"fields": ("frontier_data",)}),
    )





admin.site.register(User, UserAdmin)
