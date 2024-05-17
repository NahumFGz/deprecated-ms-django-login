from decouple import config
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)

from users.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
            "is_active",
            "is_staff",
            "is_superuser",
        )
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        return User.objects.create(**validated_data)

    def update(self, instance, validated_data):
        if "password" in validated_data:
            validated_data["password"] = make_password(validated_data["password"])
        for key, value in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        return instance

    def partial_update(self, instance, validated_data):
        if "password" in validated_data:
            validated_data["password"] = make_password(validated_data["password"])
        for key, value in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        return instance


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "No user is associated with this email address."
            )
        return value

    def save(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)
        token = default_token_generator.make_token(user)
        user.password_reset_token = token
        user.password_reset_sent_at = timezone.now()
        user.save()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        domain = config("HOST_DOMAIN")
        http_protocol = config("HTTP_HTTPS_PROTOCOL")
        link = (
            f"{http_protocol}://{domain}/api/auth/password-reset-confirm/{uid}/{token}/"
        )

        send_mail(
            "Password Reset",
            f"Click the link to reset your password: {link}",
            "from@example.com",
            [email],
            fail_silently=False,
        )


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def save(self):
        uidb64 = self.validated_data["uidb64"]
        token = self.validated_data["token"]
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid UID")

        if user.password_reset_token != token:
            raise serializers.ValidationError("Invalid token")

        # Invalidar los tokens anteriores añadiéndolos a la lista negra
        outstanding_tokens = OutstandingToken.objects.filter(user=user)
        for outstanding_token in outstanding_tokens:
            if not BlacklistedToken.objects.filter(token=outstanding_token).exists():
                BlacklistedToken.objects.create(token=outstanding_token)

        user.set_password(self.validated_data["new_password"])
        user.password_reset_token = None
        user.password_reset_sent_at = None
        user.save()
        return user
