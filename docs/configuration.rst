Configuration
=============

- **REST_AUTH_SERIALIZERS**

    You can define your custom serializers for each endpoint without overriding urls and views by adding ``REST_AUTH_SERIALIZERS`` dictionary in your django settings.
    Possible key values:

        - LOGIN_SERIALIZER - serializer class in ``rest_auth.views.LoginView``, default value ``rest_auth.serializers.LoginSerializer``

        - TOKEN_SERIALIZER - response for successful authentication in ``rest_auth.views.LoginView``, default value ``rest_auth.serializers.TokenSerializer``

        - USER_DETAILS_SERIALIZER - serializer class in ``rest_auth.views.UserDetails``, default value ``rest_auth.serializers.UserDetailsSerializer``

        - PASSWORD_RESET_SERIALIZER - serializer class in ``rest_auth.views.PasswordResetView``, default value ``rest_auth.serializers.ResetPasswordSerializer``

        - PASSWORD_RESET_CONFIRM_SERIALIZER - serializer class in ``rest_auth.views.PasswordResetFromKeyView``, default value ``rest_auth.serializers.ResetPasswordKeySerializer``

        - PASSWORD_CHANGE_SERIALIZER - serializer class in ``rest_auth.views.PasswordChangeView``, default value ``rest_auth.serializers.PasswordChangeSerializer``


    Example configuration:

    .. code-block:: python

        REST_AUTH_SERIALIZERS = {
            'LOGIN_SERIALIZER': 'path.to.custom.LoginSerializer',
            'TOKEN_SERIALIZER': 'path.to.custom.TokenSerializer',
            ...
        }


- **REST_SESSION_LOGIN** - Enable session login in Login API view (default: True)
