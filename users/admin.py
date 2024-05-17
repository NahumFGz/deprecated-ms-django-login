from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from users.models import User


# Register your models here.
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_superuser",
        "is_staff",
    )
    search_fields = ("username", "email", "first_name", "last_name")
    ordering = ("username",)
