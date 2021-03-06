from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.models import EmailAddress, EmailConfirmation
from allauth.account.utils import user_pk_to_url_str, user_username
from allauth.utils import build_absolute_uri
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.utils.translation import pgettext, ugettext_lazy as _
from rest_framework import serializers, exceptions
from rest_framework.serializers import raise_errors_on_nested_writes

from ..serializers import AuthenticationMethod, EmailVerificationMethod, UserSerializer


class PasswordField(serializers.CharField):
    def __init__(self, **kwargs):
        kwargs.setdefault('trim_whitespace', False)
        if 'style' not in kwargs:
            kwargs['style'] = {'input_type': 'password'}
        else:
            kwargs['style'].setdefault('input_type', 'password')
        super(PasswordField, self).__init__(**kwargs)


class UserDetailsSerializer(serializers.ModelSerializer):
    """
    User model w/o password
    """

    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'first_name', 'last_name')
        read_only_fields = ('email', )


class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(label=_('Password'), style={
        'input_type': 'password', 'placeholder': _('Password')})
    # remember = serializers.BooleanField(label=_('Remember Me'), required=False)

    default_error_messages = {
        'account_inactive':
        _('This account is currently inactive.'),

        'email_password_mismatch':
        _('The e-mail address and/or password you specified are not correct.'),

        'username_password_mismatch':
        _('The username and/or password you specified are not correct.'),

        'username_email_password_mismatch':
        _('The login and/or password you specified are not correct.')
    }

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        if app_settings.AUTHENTICATION_METHOD == AuthenticationMethod.EMAIL:
            login_field = serializers.EmailField(label=_('E-mail'), style={
                'input_type': 'email',
                'placeholder': _('E-mail address'),
                'autofocus': 'autofocus'
            })
        elif app_settings.AUTHENTICATION_METHOD == AuthenticationMethod.USERNAME:
            login_field = serializers.CharField(label=_('Username'), max_length=30, style={
                'placeholder': _('Username'),
                'autofocus': 'autofocus'
            })
        else:
            assert app_settings.AUTHENTICATION_METHOD == AuthenticationMethod.USERNAME_EMAIL
            login_field = serializers.CharField(label=pgettext('field label', 'Login'), style={
                'placeholder': _('Username or e-mail'),
                'autofocus': 'autofocus'
            })

        self.fields['login'] = login_field
        # TODO: set field order
        # set_form_field_order(self,  ['login', 'password', 'remember'])
        # if app_settings.SESSION_REMEMBER is not None:
        #     del self.fields['remember']

    def user_credentials(self, attrs):
        """
        Provides the credentials required to authenticate the user for
        login.
        :type attrs: OrderedDict[string, object]
        :rtype: dict[string, object]
        """
        credentials = {}
        login = attrs['login']
        if app_settings.AUTHENTICATION_METHOD == AuthenticationMethod.EMAIL:
            credentials['email'] = login
        elif app_settings.AUTHENTICATION_METHOD == AuthenticationMethod.USERNAME:
            credentials['username'] = login
        else:
            if '@' in login and '.' in login:
                credentials['email'] = login
            credentials['username'] = login
        credentials['password'] = attrs['password']
        return credentials

    def validate(self, attrs):
        from allauth.account.models import EmailAddress
        user = authenticate(**self.user_credentials(attrs))

        if user:
            if not user.is_active:
                msg = self.error_messages['account_inactive']
                raise exceptions.ValidationError(msg)

            has_verified_email = EmailAddress.objects.filter(user=user, verified=True).exists()

            if app_settings.EMAIL_VERIFICATION == EmailVerificationMethod.NONE:
                pass
            elif app_settings.EMAIL_VERIFICATION == EmailVerificationMethod.OPTIONAL:
                pass
            elif app_settings.EMAIL_VERIFICATION == EmailVerificationMethod.MANDATORY:
                if not has_verified_email:
                    msg = _('Verify Your E-mail Address')
                    raise exceptions.ValidationError(msg)
        else:
            msg = self.error_messages[
                '%s_password_mismatch' % app_settings.AUTHENTICATION_METHOD]
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs


class ChangePasswordSerializer(UserSerializer):
    oldpassword = PasswordField(label=_('Current Password'), style={
        'placeholder': _('Password')})
    password1 = PasswordField(label=_('New Password'), style={
        'placeholder': _('Password')})
    password2 = PasswordField(label=_('New Password (again)'), style={
        'placeholder': _('Password')})

    def validate_oldpassword(self, value):
        if not self.user.check_password(value):
            msg = _('Please type your current password.')
            raise serializers.ValidationError(msg)
        return value

    validate_password1 = get_adapter().clean_password

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 != password2:
            msg = _('You must type the same password each time.')
            raise serializers.ValidationError(msg)
        return attrs

    def save(self):
        get_adapter().set_password(self.user, self.validated_data['password1'])


class SetPasswordSerializer(UserSerializer):
    password1 = PasswordField(label=_('Password'), style={
        'placeholder': _('Password')})
    password2 = PasswordField(label=_('Password (again)'), style={
        'placeholder': _('Password')})

    validate_password1 = get_adapter().clean_password

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 != password2:
            msg = _('You must type the same password each time.')
            raise serializers.ValidationError(msg)
        return attrs

    def save(self):
        get_adapter().set_password(self.user, self.validated_data['password1'])


class EmailSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = EmailAddress
        read_only_fields = ('verified',)

    def __init__(self, instance=None, *args, **kwargs):
        super(EmailSerializer, self).__init__(instance, *args, **kwargs)

        # EmailAddress has change method, but coverage reports show it's unused
        # Make `email` read_only on update
        email = self.fields['email']
        email.read_only = instance is not None

    def create(self, validated_data):
        """
        :type validated_data: dict[string, object]
        :rtype: allauth.account.models.EmailAddress
        """
        raise_errors_on_nested_writes('create', self, validated_data)

        ModelClass = self.Meta.model

        instance = ModelClass.objects.add_email(self.context['request'],
                                                validated_data['user'],
                                                validated_data['email'],
                                                confirm=True)
        return instance

    def validate_email(self, value):
        """
        :type value: string
        :rtype: string
        """
        value = get_adapter().clean_email(value)
        request = self.context['request']
        errors = {
            'this_account': _('This e-mail address is already associated with '
                              'this account.'),
            'different_account': _('This e-mail address is already associated '
                                   'with another account.'),
        }
        emails = EmailAddress.objects.filter(email__iexact=value)
        if emails.filter(user=request.user).exists():
            raise serializers.ValidationError(errors['this_account'])
        if app_settings.UNIQUE_EMAIL:
            if emails.exclude(user=request.user).exists():
                raise serializers.ValidationError(errors['different_account'])
        return value


class ConfirmEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailConfirmation
        fields = ('email_address',)


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    email = serializers.EmailField(label=_('E-mail'), style={
        'input_type': 'email'})

    def validate_email(self, value):
        email = get_adapter().clean_email(value)
        self.users = get_user_model().objects.filter(
            Q(email__iexact=email) | Q(emailaddress__email__iexact=email)
        ).distinct()
        if not self.users.exists():
            msg = _('The e-mail address is not assigned to any user account')
            raise serializers.ValidationError(msg)

        return value

    def save(self, **kwargs):
        request = self.context.get('request')
        email = self.validated_data['email']
        token_generator = kwargs.get(
            'token_generator', default_token_generator)

        for user in self.users:
            temp_key = token_generator.make_token(user)

            # save it to the password reset model
            # password_reset = PasswordReset(user=user, temp_key=temp_key)
            # password_reset.save()

            current_site = Site.objects.get_current()

            # send the password reset email
            path = reverse('account_reset_password_from_key', kwargs={
                'uidb36': user_pk_to_url_str(user),
                'key': temp_key,
            })
            url = build_absolute_uri(
                request, path, protocol=app_settings.DEFAULT_HTTP_PROTOCOL)
            context = {
                'site': current_site,
                'user': user,
                'password_reset_url': url
            }
            if app_settings.AUTHENTICATION_METHOD \
                    != AuthenticationMethod.EMAIL:
                context['username'] = user_username(user)
            get_adapter().send_mail(
                'account/email/password_reset_key', email, context)

        return email


class ResetPasswordKeySerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    password1 = PasswordField(label=_('New Password'), style={
        'placeholder': _('Password')})
    password2 = PasswordField(label=_('New Password (again)'), style={
        'placeholder': _('Password')})

    def validate(self, attrs):
        if 'password1' in attrs and 'password2' in attrs:
            if attrs['password1'] != attrs['password2']:
                msg = _('You must type the same password each time.')
                raise serializers.ValidationError(msg)
        return attrs

    def save(self, user):
        get_adapter().set_password(user, self.validated_data['password1'])
