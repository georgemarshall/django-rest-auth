from allauth.account import app_settings
from rest_framework import serializers
from rest_framework.authtoken.models import Token

AuthenticationMethod = app_settings.AuthenticationMethod
EmailVerificationMethod = app_settings.EmailVerificationMethod


class UserSerializer(serializers.Serializer):
    """
    A `UserSerializer` is just a regular `Serializer`, except that:

    * A request is required as part of the context
    * A user object is automatically populated from the request
    """
    def __init__(self, *args, **kwargs):
        super(UserSerializer, self).__init__(*args, **kwargs)
        self.user = getattr(self.context['request'], 'user')


class TokenSerializer(serializers.ModelSerializer):
    """
    Serializer for Token model.
    """

    class Meta:
        model = Token
        fields = ('key',)
