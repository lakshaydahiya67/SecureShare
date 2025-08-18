import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
import tempfile
import os

User = get_user_model()


class BaseTestCase(TestCase):
    """Base test case with common setup and utilities"""
    
    def setUp(self):
        super().setUp()
        self.temp_files = []
    
    def tearDown(self):
        """Clean up any temporary files created during tests"""
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        super().tearDown()
    
    def create_test_file(self, filename, content=b"test content", content_type="text/plain"):
        """Create a temporary test file"""
        temp_file = SimpleUploadedFile(filename, content, content_type=content_type)
        return temp_file
    
    def create_temp_file_path(self, filename, content=b"test content"):
        """Create a temporary file on disk and return the path"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=filename)
        temp_file.write(content)
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name


class BaseAPITestCase(APITestCase):
    """Base API test case with authentication utilities"""
    
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.temp_files = []
    
    def tearDown(self):
        """Clean up any temporary files created during tests"""
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        super().tearDown()
    
    def authenticate_user(self, user, password='testpass123'):
        """Authenticate a user for API requests using session login"""
        # Use Django's login method for session authentication
        login_successful = self.client.login(username=user.email, password=password)
        if not login_successful:
            # Fallback to force_authenticate for unit tests where password might not be set
            self.client.force_authenticate(user=user)
        return user
    
    def unauthenticate(self):
        """Remove authentication from the client"""
        self.client.credentials()
    
    def create_test_file(self, filename, content=b"test content", content_type="text/plain"):
        """Create a temporary test file"""
        temp_file = SimpleUploadedFile(filename, content, content_type=content_type)
        return temp_file
    
    def create_temp_file_path(self, filename, content=b"test content"):
        """Create a temporary file on disk and return the path"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=filename)
        temp_file.write(content)
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name


class AuthenticatedTestMixin:
    """Mixin for tests that need authenticated users"""
    
    def create_and_authenticate_operations_user(self, email="ops@test.com", password="testpass123"):
        """Create and authenticate an operations user"""
        user = User.objects.create_user(
            email=email,
            password=password,
            user_type=User.UserType.OPERATION
        )
        user.is_email_verified = True
        user.save()
        
        if hasattr(self, 'authenticate_user'):
            self.authenticate_user(user)
        
        return user
    
    def create_and_authenticate_client_user(self, email="client@test.com", password="testpass123"):
        """Create and authenticate a client user"""
        user = User.objects.create_user(
            email=email,
            password=password,
            user_type=User.UserType.CLIENT
        )
        user.is_email_verified = True
        user.save()
        
        if hasattr(self, 'authenticate_user'):
            self.authenticate_user(user)
        
        return user


@pytest.fixture
def operations_user():
    """Pytest fixture for operations user"""
    user = User.objects.create_user(
        email="ops@test.com",
        password="testpass123",
        user_type=User.UserType.OPERATION
    )
    user.is_email_verified = True
    user.save()
    return user


@pytest.fixture
def client_user():
    """Pytest fixture for client user"""
    user = User.objects.create_user(
        email="client@test.com",
        password="testpass123",
        user_type=User.UserType.CLIENT
    )
    user.is_email_verified = True
    user.save()
    return user


@pytest.fixture
def authenticated_api_client(operations_user):
    """Pytest fixture for authenticated API client"""
    client = APIClient()
    # Use force_authenticate for pytest fixtures as it's more reliable in test environment
    client.force_authenticate(user=operations_user)
    return client


@pytest.fixture
def test_docx_file():
    """Pytest fixture for test DOCX file"""
    return SimpleUploadedFile(
        "test.docx",
        b"test docx content",
        content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )


@pytest.fixture
def test_xlsx_file():
    """Pytest fixture for test XLSX file"""
    return SimpleUploadedFile(
        "test.xlsx",
        b"test xlsx content",
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@pytest.fixture
def test_pptx_file():
    """Pytest fixture for test PPTX file"""
    return SimpleUploadedFile(
        "test.pptx",
        b"test pptx content",
        content_type="application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )