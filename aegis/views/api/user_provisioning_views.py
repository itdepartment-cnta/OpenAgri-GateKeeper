# aegis/views/api/user_provisioning_views.py

import hmac
import logging
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Q
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from aegis.models import Tenant

logger = logging.getLogger(__name__)


def _error(message, http_status, code):
    return Response({"error": message, "code": code}, status=http_status)


class TenantUserCreateAPIView(APIView):
    """
    POST /api/tenant-users/  -> creates a NON-admin user inside an existing tenant.

    Meant for a trusted backend (SheepCare), not for end users: it is guarded by a
    shared secret in the `X-Provisioning-Key` header, compared with
    `settings.USER_PROVISIONING_KEY`. If that setting is empty the endpoint is off.
    Whoever holds the key decides which tenant the user joins, so the key must stay
    on the server side.

    Body: {"tenant_id": "<uuid>" | "tenant_code": "...", "email": "...", "password": "..."}
    (`tenant_id` wins if both are sent).

    201 created | 400 invalid data | 401 bad key | 404 unknown tenant |
    409 email already registered (in any tenant, nothing is modified) | 503 disabled
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        expected = getattr(settings, "USER_PROVISIONING_KEY", "") or ""
        if not expected:
            return _error("User provisioning is not enabled.", status.HTTP_503_SERVICE_UNAVAILABLE, "disabled")

        provided = request.headers.get("X-Provisioning-Key", "")
        if not hmac.compare_digest(provided.encode(), expected.encode()):
            return _error("Invalid provisioning key.", status.HTTP_401_UNAUTHORIZED, "invalid_key")

        tenant_id = str(request.data.get("tenant_id") or "").strip()
        tenant_code = str(request.data.get("tenant_code") or "").strip().lower()
        email = str(request.data.get("email") or "").strip().lower()
        password = str(request.data.get("password") or "")
        if not (tenant_id or tenant_code) or not email or not password:
            return _error(
                "tenant_id (or tenant_code), email and password are required.",
                status.HTTP_400_BAD_REQUEST, "missing_fields",
            )

        try:
            validate_email(email)
        except ValidationError:
            return _error("Invalid email address.", status.HTTP_400_BAD_REQUEST, "invalid_email")

        if tenant_id:
            try:
                tenant = Tenant.objects.filter(id=uuid.UUID(tenant_id)).first()
            except ValueError:
                return _error("Invalid tenant_id.", status.HTTP_400_BAD_REQUEST, "invalid_tenant_id")
        else:
            tenant = Tenant.objects.filter(code=tenant_code).first()
        if not tenant:
            return _error("Tenant was not found.", status.HTTP_404_NOT_FOUND, "tenant_not_found")

        user_model = get_user_model()
        candidate = user_model(username=email, email=email)
        try:
            validate_password(password, user=candidate)
        except ValidationError as exc:
            return Response(
                {"error": "Password rejected.", "code": "weak_password", "details": list(exc.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Never reassign or modify an existing account: that is the point of the 409.
        if user_model.objects.filter(Q(username__iexact=email) | Q(email__iexact=email)).exists():
            return _error("A user with this email already exists.", status.HTTP_409_CONFLICT, "email_exists")

        try:
            with transaction.atomic():
                user = user_model.objects.create_user(username=email, email=email, password=password)
                user.tenant = tenant
                user.is_tenant_admin = False
                user.is_staff = False
                user.is_superuser = False
                user.is_active = True
                user.status = 1
                user.save()
        except IntegrityError:
            return _error("A user with this email already exists.", status.HTTP_409_CONFLICT, "email_exists")

        logger.info("Provisioned tenant user %s in tenant %s", user.uuid, tenant.code)
        return Response(
            {"uuid": str(user.uuid), "email": user.email, "tenant_code": tenant.code},
            status=status.HTTP_201_CREATED,
        )


class ChangePasswordAPIView(APIView):
    """
    POST /api/change-password/  -> the authenticated user changes their own password.
    Requires: Authorization: Bearer <access_token>

    Body: {"current_password": "...", "new_password": "..."}

    204 changed | 400 invalid or weak new password | 403 wrong current password
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        current = str(request.data.get("current_password") or "")
        new = str(request.data.get("new_password") or "")
        if not current or not new:
            return _error("current_password and new_password are required.", status.HTTP_400_BAD_REQUEST, "missing_fields")

        user = request.user
        if not user.check_password(current):
            return _error("Current password is incorrect.", status.HTTP_403_FORBIDDEN, "wrong_password")
        if new == current:
            return _error("The new password must differ from the current one.", status.HTTP_400_BAD_REQUEST, "same_password")

        try:
            validate_password(new, user=user)
        except ValidationError as exc:
            return Response(
                {"error": "Password rejected.", "code": "weak_password", "details": list(exc.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new)
        user.save(update_fields=["password"])
        return Response(status=status.HTTP_204_NO_CONTENT)
