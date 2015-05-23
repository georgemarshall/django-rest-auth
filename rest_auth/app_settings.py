from django.conf import settings

from .serializers import (
    TokenSerializer as DefaultTokenSerializer,
    UserDetailsSerializer as DefaultUserDetailsSerializer,
    LoginSerializer as DefaultLoginSerializer,
    ResetPasswordSerializer as DefaultResetPasswordSerializer,
    ResetPasswordKeySerializer as DefaultPasswordResetConfirmSerializer,
    ChangePasswordSerializer as DefaultPasswordChangeSerializer)
from .utils import import_callable


serializers = getattr(settings, 'REST_AUTH_SERIALIZERS', {})

TokenSerializer = import_callable(
    serializers.get('TOKEN_SERIALIZER', DefaultTokenSerializer)
)

UserDetailsSerializer = import_callable(
    serializers.get('USER_DETAILS_SERIALIZER', DefaultUserDetailsSerializer)
)

LoginSerializer = import_callable(
    serializers.get('LOGIN_SERIALIZER', DefaultLoginSerializer)
)

ResetPasswordSerializer = import_callable(
    serializers.get('PASSWORD_RESET_SERIALIZER', DefaultResetPasswordSerializer)
)

ResetPasswordKeySerializer = import_callable(
    serializers.get('PASSWORD_RESET_CONFIRM_SERIALIZER', DefaultPasswordResetConfirmSerializer)
)

ChangePasswordSerializer = import_callable(
    serializers.get('PASSWORD_CHANGE_SERIALIZER', DefaultPasswordChangeSerializer)
)
