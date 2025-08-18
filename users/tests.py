import pytest
from unittest.mock import patch, MagicMock
from django.test import TestCase, override_settings
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.core import mail
import uuid

from users.serializers import UserSerializer, SignupSerializer, LoginSerializer
from tests.base import BaseTestCase, BaseAPITestCase, AuthenticatedTestMixin
from tests.factories import UserFactory, OperationsUserFactory, ClientUserFactory, UnverifiedUserFactory

User = get_user_model()


@pytest.mark.models
class UserModelTests(BaseTestCase):
    """Test suite for custom User model"""
    
    def test_create_user_with_email(self):
        """Test user creation with email"""
        user = User.objects.create_user(
            email="test@example.com",
            password="testpassword123"
        )
        
        self.assertEqual(user.email, "test@example.com")
        self.assertTrue(user.check_password("testpassword123"))
        self.assertEqual(user.user_type, User.UserType.CLIENT)
        self.assertFalse(user.is_email_verified)
        self.assertIsNone(user.username)
    
    def test_create_user_without_email_raises_error(self):
        """Test user creation without email raises ValueError"""
        with self.assertRaises(ValueError) as context:
            User.objects.create_user(email="", password="testpassword123")
        
        self.assertEqual(str(context.exception), "The Email field must be set")
    
    def test_create_superuser(self):
        """Test superuser creation"""
        superuser = User.objects.create_superuser(
            email="admin@example.com",
            password="adminpassword123"
        )
        
        self.assertEqual(superuser.email, "admin@example.com")
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)
        self.assertEqual(superuser.user_type, User.UserType.OPERATION)
    
    def test_user_string_representation(self):
        """Test user string representation"""
        user = UserFactory(email="test@example.com")
        self.assertEqual(str(user), "test@example.com")
    
    def test_is_operations_user_property(self):
        """Test is_operations_user property"""
        ops_user = OperationsUserFactory()
        client_user = ClientUserFactory()
        
        self.assertTrue(ops_user.is_operations_user)
        self.assertFalse(client_user.is_operations_user)
    
    def test_is_client_user_property(self):
        """Test is_client_user property"""
        ops_user = OperationsUserFactory()
        client_user = ClientUserFactory()
        
        self.assertFalse(ops_user.is_client_user)
        self.assertTrue(client_user.is_client_user)
    
    def test_user_type_choices(self):
        """Test user type choices"""
        self.assertEqual(User.UserType.OPERATION, 'OPS')
        self.assertEqual(User.UserType.CLIENT, 'CLIENT')
        
        # Test that choices contain both options
        choices = dict(User.UserType.choices)
        self.assertIn('OPS', choices)
        self.assertIn('CLIENT', choices)
    
    def test_email_uniqueness(self):
        """Test email field uniqueness constraint"""
        UserFactory(email="unique@example.com")
        
        with self.assertRaises(Exception):  # IntegrityError in real DB
            UserFactory(email="unique@example.com")


@pytest.mark.unit
class UserManagerTests(BaseTestCase):
    """Test suite for custom UserManager"""
    
    def test_normalize_email(self):
        """Test email normalization in user creation"""
        user = User.objects.create_user(
            email="Test@EXAMPLE.COM",
            password="testpassword123"
        )
        
        self.assertEqual(user.email, "Test@example.com")
    
    def test_create_user_with_extra_fields(self):
        """Test user creation with extra fields"""
        user = User.objects.create_user(
            email="test@example.com",
            password="testpassword123",
            first_name="John",
            last_name="Doe",
            user_type=User.UserType.OPERATION
        )
        
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.user_type, User.UserType.OPERATION)
    
    def test_create_superuser_sets_defaults(self):
        """Test superuser creation sets required defaults"""
        superuser = User.objects.create_superuser(
            email="admin@example.com",
            password="adminpassword123"
        )
        
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)
        self.assertEqual(superuser.user_type, User.UserType.OPERATION)


@pytest.mark.unit
class UserSerializersTests(BaseTestCase):
    """Test suite for user serializers"""
    
    def test_user_serializer_fields(self):
        """Test UserSerializer includes correct fields"""
        user = UserFactory()
        serializer = UserSerializer(user)
        
        expected_fields = {'id', 'email', 'user_type', 'is_email_verified'}
        self.assertEqual(set(serializer.data.keys()), expected_fields)
    
    def test_user_serializer_read_only_fields(self):
        """Test UserSerializer read-only fields"""
        serializer = UserSerializer()
        self.assertIn('is_email_verified', serializer.Meta.read_only_fields)
    
    def test_signup_serializer_valid_data(self):
        """Test SignupSerializer with valid data"""
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.CLIENT
        }
        
        serializer = SignupSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_signup_serializer_password_mismatch(self):
        """Test SignupSerializer with mismatched passwords"""
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'differentpassword',
            'user_type': User.UserType.CLIENT
        }
        
        serializer = SignupSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertIn("Password fields didn't match", str(serializer.errors['password']))
    
    def test_signup_serializer_weak_password(self):
        """Test SignupSerializer with weak password"""
        data = {
            'email': 'newuser@example.com',
            'password': '123',  # Too short
            'password_confirm': '123',
            'user_type': User.UserType.CLIENT
        }
        
        serializer = SignupSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
    
    def test_signup_serializer_creates_user(self):
        """Test SignupSerializer creates user correctly"""
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.OPERATION
        }
        
        serializer = SignupSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        user = serializer.save()
        self.assertEqual(user.email, 'newuser@example.com')
        self.assertEqual(user.user_type, User.UserType.OPERATION)
        self.assertTrue(user.check_password('strongpassword123'))
    
    def test_signup_serializer_default_user_type(self):
        """Test SignupSerializer uses default user type"""
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123'
        }
        
        serializer = SignupSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        user = serializer.save()
        self.assertEqual(user.user_type, User.UserType.CLIENT)
    
    def test_login_serializer_valid_data(self):
        """Test LoginSerializer with valid data"""
        data = {
            'email': 'user@example.com',
            'password': 'password123'
        }
        
        serializer = LoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['email'], 'user@example.com')
    
    def test_login_serializer_missing_fields(self):
        """Test LoginSerializer with missing required fields"""
        # Missing email
        serializer = LoginSerializer(data={'password': 'password123'})
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        
        # Missing password
        serializer = LoginSerializer(data={'email': 'user@example.com'})
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
    
    def test_login_serializer_invalid_email(self):
        """Test LoginSerializer with invalid email format"""
        data = {
            'email': 'invalid-email',
            'password': 'password123'
        }
        
        serializer = LoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)


@pytest.mark.api
class SignupViewTests(BaseAPITestCase):
    """Test suite for SignupView API"""
    
    def setUp(self):
        super().setUp()
        self.signup_url = reverse('api-signup')
    
    @patch('users.views.send_mail')
    def test_signup_success(self, mock_send_mail):
        """Test successful user signup"""
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.CLIENT
        }
        
        response = self.client.post(self.signup_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        
        # Verify user was created
        user = User.objects.get(email='newuser@example.com')
        self.assertEqual(user.user_type, User.UserType.CLIENT)
        self.assertFalse(user.is_email_verified)
        self.assertIsNotNone(user.verification_token)
        
        # Verify email was sent
        mock_send_mail.assert_called_once()
    
    def test_signup_invalid_data(self):
        """Test signup with invalid data"""
        data = {
            'email': 'invalid-email',
            'password': '123',  # Too short
            'password_confirm': 'different',
            'user_type': 'INVALID'
        }
        
        response = self.client.post(self.signup_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertIn('user_type', response.data)
    
    def test_signup_duplicate_email(self):
        """Test signup with already existing email"""
        UserFactory(email='existing@example.com')
        
        data = {
            'email': 'existing@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123'
        }
        
        response = self.client.post(self.signup_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    @override_settings(DEBUG=True)
    @patch('users.views.send_mail')
    def test_signup_debug_mode_response(self, mock_send_mail):
        """Test signup response includes debug mode info"""
        data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123'
        }
        
        response = self.client.post(self.signup_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('debug_mode', response.data)
        self.assertTrue(response.data['debug_mode'])


@pytest.mark.api
class LoginViewTests(BaseAPITestCase):
    """Test suite for LoginView API"""
    
    def setUp(self):
        super().setUp()
        self.login_url = reverse('api-login')
        self.verified_user = UserFactory(
            email='verified@example.com',
            password='testpassword123',
            is_email_verified=True
        )
        self.unverified_client = UnverifiedUserFactory(
            email='unverified@example.com',
            password='testpassword123',
            user_type=User.UserType.CLIENT
        )
        self.unverified_ops = UnverifiedUserFactory(
            email='unverified_ops@example.com',
            password='testpassword123',
            user_type=User.UserType.OPERATION
        )
    
    def test_login_success_verified_user(self):
        """Test successful login with verified user"""
        data = {
            'email': 'verified@example.com',
            'password': 'testpassword123'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('token', response.data)  # No token in session auth
        self.assertIn('user', response.data)
        
        # Verify session was created - check if user is authenticated
        self.assertTrue('sessionid' in response.cookies or '_auth_user_id' in self.client.session)
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'email': 'verified@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid credentials')
    
    def test_login_unverified_client_user(self):
        """Test login with unverified client user"""
        data = {
            'email': 'unverified@example.com',
            'password': 'testpassword123'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Email not verified')
    
    def test_login_unverified_operations_user_allowed(self):
        """Test login with unverified operations user (should be allowed)"""
        data = {
            'email': 'unverified_ops@example.com',
            'password': 'testpassword123'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('token', response.data)  # No token in session auth
        self.assertIn('user', response.data)
    
    def test_login_missing_fields(self):
        """Test login with missing required fields"""
        # Missing password
        response = self.client.post(self.login_url, {'email': 'test@example.com'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Missing email
        response = self.client.post(self.login_url, {'password': 'password123'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_login_nonexistent_user(self):
        """Test login with non-existent user"""
        data = {
            'email': 'nonexistent@example.com',
            'password': 'password123'
        }
        
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['error'], 'Invalid credentials')


@pytest.mark.api
class VerifyEmailViewTests(BaseAPITestCase):
    """Test suite for VerifyEmailView API"""
    
    def setUp(self):
        super().setUp()
        self.unverified_user = UnverifiedUserFactory(
            email='unverified@example.com',
            verification_token='test-token-123'
        )
        self.verified_user = UserFactory(
            email='verified@example.com',
            is_email_verified=True,
            verification_token='already-used-token'
        )
    
    def test_verify_email_success(self):
        """Test successful email verification"""
        url = reverse('verify-email', kwargs={'token': 'test-token-123'})
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify user was updated
        self.unverified_user.refresh_from_db()
        self.assertTrue(self.unverified_user.is_email_verified)
        self.assertIsNone(self.unverified_user.verification_token)
    
    def test_verify_email_already_verified(self):
        """Test verification of already verified email"""
        url = reverse('verify-email', kwargs={'token': 'already-used-token'})
        
        response = self.client.get(url)
        
        # Should render template with error message
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already verified', response.content.decode())
    
    def test_verify_email_invalid_token(self):
        """Test verification with invalid token"""
        url = reverse('verify-email', kwargs={'token': 'invalid-token'})
        
        response = self.client.get(url)

        # Should render template with error message
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('No User matches the given query', response.content.decode())
    
    def test_verify_email_api_request_success(self):
        """Test API verification request (JSON response)"""
        url = reverse('verify-email', kwargs={'token': 'test-token-123'})
        
        response = self.client.get(url, HTTP_ACCEPT='application/json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Email verified successfully.')
    
    def test_verify_email_api_request_already_verified(self):
        """Test API verification request for already verified email"""
        url = reverse('verify-email', kwargs={'token': 'already-used-token'})
        
        response = self.client.get(url, HTTP_ACCEPT='application/json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('message', response.data)


@pytest.mark.integration
class UserAuthenticationFlowTests(BaseAPITestCase):
    """Integration tests for complete user authentication flow"""
    
    @patch('users.views.send_mail')
    def test_complete_signup_verification_login_flow(self, mock_send_mail):
        """Test complete flow: signup -> verify email -> login"""
        # Step 1: Signup
        signup_data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.CLIENT
        }
        
        signup_response = self.client.post(reverse('api-signup'), signup_data)
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        
        # Get the created user
        user = User.objects.get(email='newuser@example.com')
        self.assertFalse(user.is_email_verified)
        self.assertIsNotNone(user.verification_token)
        
        # Step 2: Verify email
        verify_url = reverse('verify-email', kwargs={'token': user.verification_token})
        verify_response = self.client.get(verify_url)
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        
        # Check user is now verified
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        self.assertIsNone(user.verification_token)
        
        # Step 3: Login
        login_data = {
            'email': 'newuser@example.com',
            'password': 'strongpassword123'
        }
        
        login_response = self.client.post(reverse('api-login'), login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertNotIn('token', login_response.data)  # Session auth doesn't return tokens
        self.assertIn('user', login_response.data)
        
        # Verify email was sent during signup
        mock_send_mail.assert_called_once()
    
    def test_unverified_client_cannot_login(self):
        """Test that unverified client users cannot login"""
        # Signup
        signup_data = {
            'email': 'unverified@example.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.CLIENT
        }
        
        with patch('django.core.mail.send_mail'):
            signup_response = self.client.post(reverse('api-signup'), signup_data)
        
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        
        # Try to login without verification
        login_data = {
            'email': 'unverified@example.com',
            'password': 'strongpassword123'
        }
        
        login_response = self.client.post(reverse('api-login'), login_data)
        self.assertEqual(login_response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(login_response.data['error'], 'Email not verified')
