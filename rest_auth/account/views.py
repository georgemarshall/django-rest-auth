from allauth.account import app_settings, signals
from allauth.account.utils import complete_signup, url_str_to_user_pk
from allauth.account.views import SignupView as AllauthSignupView, ConfirmEmailView as AllauthConfirmEmailView
from django.contrib.auth import user_logged_in, user_logged_out
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpRequest
from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _
from rest_framework import viewsets, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import detail_route, list_route
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_auth.app_settings import LoginSerializer, UserDetailsSerializer, ResetPasswordSerializer, \
    ResetPasswordKeySerializer, ChangePasswordSerializer, SetPasswordSerializer
from rest_auth.views import User


class SignupView(APIView, AllauthSignupView):
    permission_classes = (AllowAny,)
    user_serializer_class = UserDetailsSerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def form_valid(self, form):
        self.user = form.save(self.request)
        if isinstance(self.request, HttpRequest):
            request = self.request
        else:
            request = self.request._request
        return complete_signup(request, self.user,
                               app_settings.EMAIL_VERIFICATION,
                               self.get_success_url())

    def post(self, request, *args, **kwargs):
        self.initial = {}
        self.request.POST = self.request.DATA.copy()
        form_class = self.get_form_class()
        self.form = self.get_form(form_class)
        if self.form.is_valid():
            self.form_valid(self.form)
            return self.get_response()
        else:
            return self.get_response_with_errors()

    def get_response(self):
        serializer = self.user_serializer_class(instance=self.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get_response_with_errors(self):
        return Response(self.form.errors, status=status.HTTP_400_BAD_REQUEST)

signup = SignupView.as_view()


class LoginView(GenericAPIView):
    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: username, password
    Return the REST Framework Token Object's key.
    """
    throttle_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request):
        """
        :type request: Request
        :rtype: Response
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        user_logged_in.send(sender=user.__class__, request=request, user=user)
        return Response({'token': token.key})

login = LoginView.as_view()


class LogoutView(APIView):
    """
    Calls Django logout method and delete the Token object
    assigned to the current User object.

    Accepts/Returns nothing.
    """
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        """
        :type request: Request
        :rtype: Response
        """
        message = render_to_string('account/messages/logged_out.txt').strip()
        user = getattr(request, 'user', None)
        if hasattr(user, 'is_authenticated') and not user.is_authenticated():
            user = None

        if request.auth:
            request.auth.delete()
        user_logged_out.send(sender=user.__class__, request=request, user=user)
        return Response({'success': message})

logout = LogoutView.as_view()


class PasswordChangeView(GenericAPIView):
    """
    Accepts the following POST parameters: [oldpassword,] password1, password2
    Returns the success/fail message.
    """
    throttle_classes = ()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    def get_serializer_class(self):
        """
        Returns ``ChangePasswordSerializer`` if the user passes
        ``has_usable_password`` otherwise we assume their account was created
        via a social login and use ``SetPasswordSerializer``.

        :rtype: ChangePasswordSerializer | SetPasswordSerializer
        """
        user = getattr(self.request, 'user')
        if user.has_usable_password():
            return ChangePasswordSerializer
        else:
            return SetPasswordSerializer

    def post(self, request):
        """
        :type request: Request
        :rtype: Response
        """
        user = getattr(request, 'user', None)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if isinstance(serializer, ChangePasswordSerializer):
            message = render_to_string('account/messages/password_changed.txt').strip()
            signals.password_changed.send(sender=user.__class__, request=request, user=user)
            return Response({"success": message})
        elif isinstance(serializer, SetPasswordSerializer):
            message = render_to_string('account/messages/password_set.txt').strip()
            signals.password_set.send(sender=user.__class__, request=request, user=user)
            return Response({"success": message})

password_change = PasswordChangeView.as_view()
password_set = PasswordChangeView.as_view()


class EmailView(GenericAPIView):
    pass

email = EmailView.as_view()


class ConfirmEmailView(APIView, AllauthConfirmEmailView):

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        self.kwargs['key'] = self.request.DATA.get('key', '')
        confirmation = self.get_object()
        confirmation.confirm(self.request)
        return Response({'message': 'ok'}, status=status.HTTP_200_OK)


confirm_email = ConfirmEmailView.as_view()


class PasswordResetView(GenericAPIView):
    """
    Calls Django Auth PasswordResetForm save method.

    Accepts the following POST parameters: email
    Returns the success/fail message.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        """
        :type request: Request
        :rtype: Response
        """
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        # Return the success message with OK HTTP status
        return Response({'success': _(
            "We have sent you an e-mail. Please contact us if you do not "
            "receive it within a few minutes.")})

password_reset = PasswordResetView.as_view()


class PasswordResetFromKeyView(GenericAPIView):
    """
    Password reset e-mail link is confirmed, therefore this resets the user's password.

    Accepts the following POST parameters: new_password1, new_password2
    Accepts the following Django URL arguments: token, uid
    Returns the success/fail message.
    """
    serializer_class = ResetPasswordKeySerializer
    permission_classes = (AllowAny,)
    token_generator = default_token_generator

    def _get_user(self, uidb36):
        """
        Return user for `uidb36`

        :type uidb36: string
        :rtype: User
        """
        try:
            pk = url_str_to_user_pk(uidb36)
        except ValueError:
            raise NotFound
        return get_object_or_404(User, pk=pk)

    def initial(self, request, uidb36, key, *args, **kwargs):
        """
        :type request: Request
        :type uidb36: string
        :type key: string
        :rtype: None
        """
        super(PasswordResetFromKeyView, self).initial(request, uidb36, key, *args, **kwargs)
        self.reset_user = self._get_user(uidb36)
        if not self.token_generator.check_token(self.reset_user, key):
            raise PermissionDenied(_("Bad Token"))

    def post(self, request, *args, **kwargs):
        """
        :type request: Request
        :rtype: Response
        """
        message = render_to_string('account/messages/password_changed.txt').strip()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=self.reset_user)

        signals.password_reset.send(sender=self.reset_user.__class__,
                                    request=request, user=self.reset_user)
        return Response({"success": message})

password_reset_from_key = PasswordResetFromKeyView.as_view()
