from rest_auth.registration.serializers import SocialLoginSerializer
from rest_auth.account.views import LoginView


class SocialLoginView(LoginView):
    """
    class used for social authentications
    example usage for facebook

    from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
    class FacebookLogin(SocialLoginView):
        adapter_class = FacebookOAuth2Adapter
    """

    serializer_class = SocialLoginSerializer
