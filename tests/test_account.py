from allauth.account.models import EmailAddress
from allauth.account.utils import user_pk_to_url_str
from django.conf.urls import include, url
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.urlresolvers import reverse
from django.test import override_settings
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

# Include allauth.urls
urlpatterns = [
    url(r'^allauth/', include('allauth.urls')),
    url(r'^api/', include('rest_auth.urls')),
]

User = get_user_model()

class TestSignup(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.url = reverse('rest_signup')

    def test_empty_registration(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration(self):
        response = self.client.post(self.url, {
            'username': 'person',
            'password1': 'person',
            'password2': 'person'
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_existing_registration(self):
        User.objects.create_user('person', 'person@example.com', 'person')

        response = self.client.post(self.url, {
            'username': 'person',
            'password1': 'person',
            'password2': 'person'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        ACCOUNT_EMAIL_VERIFICATION='mandatory',
        ACCOUNT_EMAIL_REQUIRED=True
    )
    def test_registration_with_email_verificaiton(self):
        response = self.client.post(self.url, {
            'username': 'person',
            'email': 'person@example.com',
            'password1': 'person',
            'password2': 'person'
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(len(mail.outbox), 1)


class TestLogin(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.url = reverse('rest_login')
        self.user_credentials = {
            'email': 'person@example.com',
            'username': 'person',
            'password': 'person'
        }
        self.user = User.objects.create_user(**self.user_credentials)

    def test_inactive_login(self):
        self.user.is_active = False
        self.user.save()

        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_invalid_login(self):
        response = self.client.post(self.url, {
            'login': 'bad_user',
            'password': 'bad_password'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    @override_settings(ACCOUNT_AUTHENTICATION_METHOD='username')
    def test_username_login(self):
        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    @override_settings(ACCOUNT_AUTHENTICATION_METHOD='email')
    def test_email_login(self):
        response = self.client.post(self.url, {
            'login': self.user_credentials['email'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    @override_settings(ACCOUNT_AUTHENTICATION_METHOD='username_email')
    def test_username_email_login(self):
        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

        response = self.client.post(self.url, {
            'login': self.user_credentials['email'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    @override_settings(ACCOUNT_EMAIL_VERIFICATION='none')
    def test_email_verification_none(self):
        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

        EmailAddress.objects.create(user=self.user,
                                    email=self.user_credentials['email'],
                                    verified=True,
                                    primary=True)

        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    @override_settings(ACCOUNT_EMAIL_VERIFICATION='optional')
    def test_email_verification_optional(self):
        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

        EmailAddress.objects.create(user=self.user,
                                    email=self.user_credentials['email'],
                                    verified=True,
                                    primary=True)

        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    @override_settings(ACCOUNT_EMAIL_VERIFICATION='mandatory')
    def test_email_verification_mandatory(self):
        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

        EmailAddress.objects.create(user=self.user,
                                    email=self.user_credentials['email'],
                                    verified=True,
                                    primary=True)

        response = self.client.post(self.url, {
            'login': self.user_credentials['username'],
            'password': self.user_credentials['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)


class TestLogout(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.url = reverse('rest_logout')
        self.user = User.objects.create_user('person', 'person@example.com', 'person')
        self.token = Token.objects.create(user=self.user)

    def test_logout_no_user(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout(self):
        self.client.credentials(HTTP_AUTHORIZATION='Token {}'.format(self.token))

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)

        token = Token.objects.filter(user=self.user).exists()
        self.assertFalse(token)

        # def test_logout_without_session(self):
        #     self.client.login(username='person', password='person')
        #
        #     response = self.client.post(self.url)
        #     self.assertEqual(response.status_code, status.HTTP_200_OK)
        #     # self.assertNotIn(SESSION_KEY, self.client.session)


class TestPasswordChange(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.user_credentials = {'username': 'person', 'password': 'person'}
        self.user = User.objects.create_user(**self.user_credentials)
        self.url = reverse('rest_change_password')

    def test_unauthenticated(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_empty_fields(self):
        self.client.login(**self.user_credentials)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('oldpassword', response.data)
        self.assertIn('password1', response.data)
        self.assertIn('password2', response.data)

    def test_mismatched_password(self):
        self.client.login(**self.user_credentials)
        response = self.client.post(self.url, {
            'oldpassword': self.user_credentials['password'],
            'password1': 'new_person1',
            'password2': 'new_person'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_incorrect_password(self):
        self.client.login(**self.user_credentials)
        response = self.client.post(self.url, {
            'oldpassword': 'password',
            'password1': 'new_person',
            'password2': 'new_person'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('oldpassword', response.data)

    @override_settings(ACCOUNT_PASSWORD_MIN_LENGTH=20)
    def test_minimum_length_password(self):
        self.client.login(**self.user_credentials)
        response = self.client.post(self.url, {
            'oldpassword': self.user_credentials['password'],
            'password1': 'new_person',
            'password2': 'new_person'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password1', response.data)

    def test_whitespace_password_change(self):
        self.user_credentials['password'] = ' person '
        self.user.set_password(self.user_credentials['password'])
        self.user.save()

        self.client.login(**self.user_credentials)
        response = self.client.post(self.url, {
            'oldpassword': self.user_credentials['password'],
            'password1': ' new_person ',
            'password2': ' new_person '
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)

        self.user_credentials['password'] = ' new_person '
        response = self.client.post(self.url, {
            'oldpassword': self.user_credentials['password'],
            'password1': 'new_person',
            'password2': 'new_person'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)

    def test_password_change(self):
        self.client.login(**self.user_credentials)
        response = self.client.post(self.url, {
            'oldpassword': self.user_credentials['password'],
            'password1': 'new_person',
            'password2': 'new_person'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)


class TestPasswordSet(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.user = User.objects.create_user('person')
        self.url = reverse('rest_set_password')

    def test_unauthenticated(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_empty_fields(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password1', response.data)
        self.assertIn('password2', response.data)

    def test_set_password(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.post(self.url, {
            'password1': 'new_person',
            'password2': 'new_person'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)


class TestEmail(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.url = reverse('rest_email')
        self.user = User.objects.create_user('person')
        self.email = EmailAddress.objects.create(user=self.user,
                                                 email='person@example.com')

    def test_add_empty_email(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_email(self):
        response = self.client.post(self.url, {'email': self.email.email})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

    def test_add_existing_email(self):
        self.test_add_email()

        response = self.client.post(self.url, {'email': self.email.email})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(ACCOUNT_UNIQUE_EMAIL=True)
    def test_add_unique_email(self):
        response = self.client.post(self.url, {'email': self.email.email})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_email(self):
        self.test_add_email()

        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_email(self):
        self.test_add_email()

        response = self.client.put(self.url, {'primary': True})
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class TestConfirmEmail(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.url = reverse('rest_confirm_email', kwargs={
            'key': None
        })

    def test_invalid_key(self):
        response = self.client.get(reverse('rest_confirm_email', kwargs={
            'key': 'abcdef'
        }))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_email_confirm(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class TestPasswordReset(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.url = reverse('rest_reset_password')
        self.user = User.objects.create_user('person', 'person@example.com', 'person')

    def test_empty_password_reset(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset(self):
        response = self.client.post(self.url, {'email': self.user.email})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

    def test_password_reset_with_bad_email(self):
        response = self.client.post(self.url, {'email': 'bad@example.com'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(len(mail.outbox), 0)


class TestPasswordResetFromKey(APITestCase):
    urls = 'tests.test_account'

    def setUp(self):
        self.user = User.objects.create_user('person')
        self.url = reverse('rest_reset_password_from_key', kwargs={
            'uidb36': user_pk_to_url_str(self.user),
            'key': default_token_generator.make_token(self.user),
        })

    def test_invalid_token(self):
        # Invalid key
        response = self.client.post(reverse('rest_reset_password_from_key', kwargs={
            'uidb36': user_pk_to_url_str(self.user),
            'key': 'abcdef',
        }))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Invalid uidb36
        response = self.client.post(reverse('rest_reset_password_from_key', kwargs={
            'uidb36': '16',
            'key': default_token_generator.make_token(self.user),
        }))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_empty_password_reset_confirm(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_confirm(self):
        response = self.client.post(self.url, {
            'password1': 'new_person',
            'password2': 'new_person',
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_confirm_mismatched(self):
        response = self.client.post(self.url, {
            'password1': 'new_person1',
            'password2': 'new_person',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_single_use(self):
        self.test_password_reset_confirm()

        response = self.client.post(self.url, {
            'password1': 'new_person',
            'password2': 'new_person',
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
