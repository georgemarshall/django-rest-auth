from django.conf import settings

from .account.serializers import (
    UserDetailsSerializer as DefaultUserDetailsSerializer,
    LoginSerializer as DefaultLoginSerializer,
    ChangePasswordSerializer as DefaultChangePasswordSerializer,
    SetPasswordSerializer as DefaultSetPasswordSerializer,
    EmailSerializer as DefaultEmailSerializer,
    ConfirmEmailSerializer as DefaultConfirmEmailSerializer,
    ResetPasswordSerializer as DefaultResetPasswordSerializer,
    ResetPasswordKeySerializer as DefaultPasswordResetConfirmSerializer,
)
from .serializers import (
    TokenSerializer as DefaultTokenSerializer,
)
from .utils import import_callable


serializers = getattr(settings, 'REST_AUTH_SERIALIZERS', {})

UserDetailsSerializer = import_callable(
    serializers.get('USER_DETAILS_SERIALIZER', DefaultUserDetailsSerializer)
)

LoginSerializer = import_callable(
    serializers.get('LOGIN_SERIALIZER', DefaultLoginSerializer)
)

ChangePasswordSerializer = import_callable(
    serializers.get('PASSWORD_CHANGE_SERIALIZER', DefaultChangePasswordSerializer)
)

SetPasswordSerializer = import_callable(
    serializers.get('PASSWORD_SET_SERIALIZER', DefaultSetPasswordSerializer)
)

EmailSerializer = import_callable(
    serializers.get('EMAIL_SERIALIZER', DefaultEmailSerializer)
)

ConfirmEmailSerializer = import_callable(
    serializers.get('CONFIRM_EMAIL_SERIALIZER', DefaultConfirmEmailSerializer)
)

ResetPasswordSerializer = import_callable(
    serializers.get('PASSWORD_RESET_SERIALIZER', DefaultResetPasswordSerializer)
)

ResetPasswordKeySerializer = import_callable(
    serializers.get('PASSWORD_RESET_CONFIRM_SERIALIZER', DefaultPasswordResetConfirmSerializer)
)

TokenSerializer = import_callable(
    serializers.get('TOKEN_SERIALIZER', DefaultTokenSerializer)
)
