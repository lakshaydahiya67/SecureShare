import pytest
from unittest.mock import patch, mock_open, MagicMock
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.http import FileResponse
from rest_framework import status
from rest_framework.test import APITestCase
import os
import tempfile
from datetime import timedelta
import uuid

from files.models import File, FileAccess, get_file_path
from files.serializers import FileSerializer, FileListSerializer, FileDownloadSerializer
from core.encryption import encrypt_url_token, decrypt_url_token
from tests.base import BaseTestCase, BaseAPITestCase, AuthenticatedTestMixin
from tests.factories import (
    UserFactory, OperationsUserFactory, ClientUserFactory,
    FileFactory, DocxFileFactory, XlsxFileFactory, PptxFileFactory,
    FileAccessFactory, ExpiredFileAccessFactory, UsedFileAccessFactory,
    InvalidFileTypeFactory
)

User = get_user_model()


@pytest.mark.models
class FileModelTests(BaseTestCase):
    """Test suite for File model"""
    
    def test_file_creation(self):
        """Test basic file creation"""
        user = OperationsUserFactory()
        file_obj = FileFactory(
            title="Test Document",
            uploaded_by=user
        )
        
        self.assertEqual(file_obj.title, "Test Document")
        self.assertEqual(file_obj.uploaded_by, user)
        self.assertIsNotNone(file_obj.uploaded_at)
    
    def test_file_string_representation(self):
        """Test file string representation"""
        file_obj = FileFactory(title="My Document")
        self.assertEqual(str(file_obj), "My Document")
    
    def test_file_extension_property(self):
        """Test file extension property"""
        file_obj = DocxFileFactory()
        # Since we're using factories, the extension should be extracted from the file name
        self.assertIn('docx', file_obj.extention.lower())
    
    def test_file_filename_property(self):
        """Test file filename property"""
        file_obj = FileFactory()
        # The filename should be the basename of the file path
        filename = file_obj.filename
        self.assertIsInstance(filename, str)
        self.assertGreater(len(filename), 0)
    
    def test_allowed_extensions(self):
        """Test allowed file extensions"""
        expected_extensions = ['pptx', 'docx', 'xlsx']
        self.assertEqual(File.ALLOWED_EXTENTIONS, expected_extensions)
    
    def test_get_file_path_function(self):
        """Test get_file_path function for file uploads"""
        # Mock file instance
        instance = MagicMock()
        filename = "test_document.docx"
        
        result_path = get_file_path(instance, filename)
        
        # Should start with uploads/
        self.assertTrue(result_path.startswith('uploads/'))
        # Should end with .docx
        self.assertTrue(result_path.endswith('.docx'))
        # Should contain a UUID (36 characters + .docx = 41 total)
        path_parts = result_path.split('/')
        file_part = path_parts[-1]  # Get the filename part
        uuid_part = file_part.split('.')[0]  # Get UUID part before extension
        self.assertEqual(len(uuid_part), 36)  # UUID4 length


@pytest.mark.models
class FileAccessModelTests(BaseTestCase):
    """Test suite for FileAccess model"""
    
    def test_file_access_creation(self):
        """Test FileAccess model creation"""
        file_obj = FileFactory()
        file_access = FileAccessFactory(file=file_obj)
        
        self.assertEqual(file_access.file, file_obj)
        self.assertIsNotNone(file_access.access_token)
        self.assertIsNotNone(file_access.created_at)
        self.assertIsNotNone(file_access.expires_at)
        self.assertFalse(file_access.is_used)
    
    def test_file_access_string_representation(self):
        """Test FileAccess string representation"""
        file_obj = FileFactory(title="Test Document")
        file_access = FileAccessFactory(file=file_obj)
        
        expected_str = f"Access for {file_obj.title}"
        self.assertEqual(str(file_access), expected_str)
    
    def test_file_access_token_uniqueness(self):
        """Test that access tokens are unique"""
        file_obj = FileFactory()
        access1 = FileAccessFactory(file=file_obj)
        access2 = FileAccessFactory(file=file_obj)
        
        self.assertNotEqual(access1.access_token, access2.access_token)
    
    def test_expired_file_access(self):
        """Test expired file access"""
        file_access = ExpiredFileAccessFactory()
        
        self.assertTrue(file_access.expires_at < timezone.now())
    
    def test_used_file_access(self):
        """Test used file access"""
        file_access = UsedFileAccessFactory()
        
        self.assertTrue(file_access.is_used)


@pytest.mark.unit
class FileSerializersTests(BaseTestCase):
    """Test suite for file serializers"""
    
    def setUp(self):
        super().setUp()
        self.user = OperationsUserFactory()
        self.request_mock = MagicMock()
        self.request_mock.user = self.user
    
    def test_file_serializer_fields(self):
        """Test FileSerializer includes correct fields"""
        file_obj = FileFactory()
        serializer = FileSerializer(file_obj)
        
        expected_fields = {'id', 'title', 'file', 'uploaded_by', 'uploaded_at'}
        self.assertEqual(set(serializer.data.keys()), expected_fields)
    
    def test_file_serializer_read_only_fields(self):
        """Test FileSerializer read-only fields"""
        serializer = FileSerializer()
        expected_readonly = ['uploaded_by', 'uploaded_at']
        self.assertEqual(serializer.Meta.read_only_fields, expected_readonly)
    
    def test_file_serializer_valid_file_validation(self):
        """Test FileSerializer file validation with valid file"""
        valid_file = SimpleUploadedFile(
            "test.docx",
            b"test content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        data = {'title': 'Test Document', 'file': valid_file}
        serializer = FileSerializer(data=data, context={'request': self.request_mock})
        
        self.assertTrue(serializer.is_valid())
    
    def test_file_serializer_invalid_file_validation(self):
        """Test FileSerializer file validation with invalid file"""
        invalid_file = SimpleUploadedFile(
            "test.txt",
            b"test content",
            content_type="text/plain"
        )
        
        data = {'title': 'Test Document', 'file': invalid_file}
        serializer = FileSerializer(data=data, context={'request': self.request_mock})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('file', serializer.errors)
    
    def test_file_serializer_create_sets_uploaded_by(self):
        """Test FileSerializer create method sets uploaded_by"""
        valid_file = SimpleUploadedFile(
            "test.docx",
            b"test content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        data = {'title': 'Test Document', 'file': valid_file}
        serializer = FileSerializer(data=data, context={'request': self.request_mock})
        
        self.assertTrue(serializer.is_valid())
        file_obj = serializer.save()
        
        self.assertEqual(file_obj.uploaded_by, self.user)
    
    def test_file_list_serializer_fields(self):
        """Test FileListSerializer includes correct fields"""
        file_obj = FileFactory()
        serializer = FileListSerializer(file_obj)
        
        expected_fields = {'id', 'title', 'uploaded_at'}
        self.assertEqual(set(serializer.data.keys()), expected_fields)
    
    def test_file_download_serializer_fields(self):
        """Test FileDownloadSerializer fields"""
        data = {
            'download_link': 'https://example.com/download/token123',
            'message': 'success'
        }
        
        serializer = FileDownloadSerializer(data)
        
        expected_fields = {'download_link', 'message'}
        self.assertEqual(set(serializer.data.keys()), expected_fields)
        self.assertEqual(serializer.data['download_link'], data['download_link'])
        self.assertEqual(serializer.data['message'], data['message'])


@pytest.mark.api
class FileUploadViewTests(BaseAPITestCase, AuthenticatedTestMixin):
    """Test suite for FileUploadView API"""
    
    def setUp(self):
        super().setUp()
        self.upload_url = reverse('api-file-upload')
    
    def test_upload_success_operations_user(self):
        """Test successful file upload by operations user"""
        user = self.create_and_authenticate_operations_user()
        
        file_data = SimpleUploadedFile(
            "test.docx",
            b"test document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        data = {
            'title': 'Test Document',
            'file': file_data
        }
        
        response = self.client.post(self.upload_url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)
        self.assertEqual(response.data['title'], 'Test Document')
        self.assertEqual(response.data['uploaded_by'], user.id)
        
        # Verify file was created in database
        file_obj = File.objects.get(id=response.data['id'])
        self.assertEqual(file_obj.title, 'Test Document')
        self.assertEqual(file_obj.uploaded_by, user)
    
    def test_upload_denied_client_user(self):
        """Test file upload denied for client user"""
        self.create_and_authenticate_client_user()
        
        file_data = SimpleUploadedFile(
            "test.docx",
            b"test document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        data = {
            'title': 'Test Document',
            'file': file_data
        }
        
        response = self.client.post(self.upload_url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_upload_denied_unauthenticated(self):
        """Test file upload denied for unauthenticated user"""
        file_data = SimpleUploadedFile(
            "test.docx",
            b"test document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        data = {
            'title': 'Test Document',
            'file': file_data
        }
        
        response = self.client.post(self.upload_url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_upload_invalid_file_type(self):
        """Test file upload with invalid file type"""
        self.create_and_authenticate_operations_user()
        
        file_data = SimpleUploadedFile(
            "test.txt",
            b"test content",
            content_type="text/plain"
        )
        
        data = {
            'title': 'Test Document',
            'file': file_data
        }
        
        response = self.client.post(self.upload_url, data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('file', response.data)
    
    def test_upload_missing_required_fields(self):
        """Test file upload with missing required fields"""
        self.create_and_authenticate_operations_user()
        
        # Missing title
        file_data = SimpleUploadedFile(
            "test.docx",
            b"test content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        response = self.client.post(self.upload_url, {'file': file_data}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('title', response.data)
        
        # Missing file
        response = self.client.post(self.upload_url, {'title': 'Test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('file', response.data)


@pytest.mark.api
class FileListViewTests(BaseAPITestCase, AuthenticatedTestMixin):
    """Test suite for FileListView API"""
    
    def setUp(self):
        super().setUp()
        self.list_url = reverse('api-file-list')
        
        # Create test files
        self.ops_user = OperationsUserFactory()
        self.file1 = FileFactory(title="File 1", uploaded_by=self.ops_user)
        self.file2 = FileFactory(title="File 2", uploaded_by=self.ops_user)
        self.file3 = FileFactory(title="File 3", uploaded_by=self.ops_user)
    
    def test_list_files_operations_user(self):
        """Test file listing for operations user"""
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)
        
        # Check response format
        for file_data in response.data:
            self.assertIn('id', file_data)
            self.assertIn('title', file_data)
            self.assertIn('uploaded_at', file_data)
            # Should not include sensitive fields
            self.assertNotIn('file', file_data)
            self.assertNotIn('uploaded_by', file_data)
    
    def test_list_files_client_user(self):
        """Test file listing for client user"""
        self.create_and_authenticate_client_user()
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)  # Client users can see all files
    
    def test_list_files_unauthenticated(self):
        """Test file listing denied for unauthenticated user"""
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_list_files_ordered_by_upload_date(self):
        """Test files are ordered by upload date (newest first)"""
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that files are ordered by uploaded_at descending
        uploaded_dates = [file_data['uploaded_at'] for file_data in response.data]
        sorted_dates = sorted(uploaded_dates, reverse=True)
        self.assertEqual(uploaded_dates, sorted_dates)


@pytest.mark.api
class FileDownloadLinkViewTests(BaseAPITestCase, AuthenticatedTestMixin):
    """Test suite for FileDownloadLinkView API"""
    
    def setUp(self):
        super().setUp()
        self.file_obj = FileFactory()
        self.download_link_url = reverse('api-file-download-link', kwargs={'file_id': self.file_obj.id})
    
    def test_get_download_link_success(self):
        """Test successful download link generation"""
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.download_link_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('download_link', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'success')
        
        # Verify download link format
        download_link = response.data['download_link']
        self.assertIn('/api/files/download/', download_link)
        
        # Verify FileAccess was created
        file_access = FileAccess.objects.filter(file=self.file_obj).first()
        self.assertIsNotNone(file_access)
        self.assertFalse(file_access.is_used)
        self.assertTrue(file_access.expires_at > timezone.now())
    
    def test_get_download_link_client_user(self):
        """Test download link generation for client user"""
        self.create_and_authenticate_client_user()
        
        response = self.client.get(self.download_link_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_get_download_link_unauthenticated(self):
        """Test download link generation denied for unauthenticated user"""
        response = self.client.get(self.download_link_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_get_download_link_nonexistent_file(self):
        """Test download link generation for nonexistent file"""
        self.create_and_authenticate_operations_user()
        
        invalid_url = reverse('api-file-download-link', kwargs={'file_id': 99999})
        response = self.client.get(invalid_url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


@pytest.mark.api
class FileDownloadViewTests(BaseAPITestCase):
    """Test suite for FileDownloadView API"""
    
    def setUp(self):
        super().setUp()
        self.file_obj = FileFactory()
        self.file_access = FileAccessFactory(file=self.file_obj)
        self.encrypted_token = encrypt_url_token(str(self.file_access.access_token))
        self.download_url = reverse('api-file-download', kwargs={'token': self.encrypted_token})
    
    @patch('builtins.open', mock_open(read_data=b"file content"))
    @patch('os.path.exists', return_value=True)
    def test_download_file_success(self, mock_exists):
        """Test successful file download"""
        response = self.client.get(self.download_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response, FileResponse)
        
        # Verify FileAccess was marked as used
        self.file_access.refresh_from_db()
        self.assertTrue(self.file_access.is_used)
    
    def test_download_file_invalid_token(self):
        """Test file download with invalid token"""
        invalid_url = reverse('api-file-download', kwargs={'token': 'invalid-token'})
        response = self.client.get(invalid_url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn('Invalid or expired', response.data['error'])
    
    def test_download_file_expired_access(self):
        """Test file download with expired access"""
        expired_access = ExpiredFileAccessFactory(file=self.file_obj)
        encrypted_token = encrypt_url_token(str(expired_access.access_token))
        download_url = reverse('api-file-download', kwargs={'token': encrypted_token})
        
        response = self.client.get(download_url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn('expired', response.data['error'])
    
    def test_download_file_already_used(self):
        """Test file download with already used access"""
        used_access = UsedFileAccessFactory(file=self.file_obj)
        encrypted_token = encrypt_url_token(str(used_access.access_token))
        download_url = reverse('api-file-download', kwargs={'token': encrypted_token})
        
        response = self.client.get(download_url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn('already used', response.data['error'])
    
    def test_download_file_nonexistent_access(self):
        """Test file download with nonexistent access token"""
        fake_token = encrypt_url_token(str(uuid.uuid4()))
        download_url = reverse('api-file-download', kwargs={'token': fake_token})
        
        response = self.client.get(download_url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn('Invalid download link', response.data['error'])


@pytest.mark.api
class FileSummarizeViewTests(BaseAPITestCase, AuthenticatedTestMixin):
    """Test suite for FileSummarizeView API"""
    
    def setUp(self):
        super().setUp()
        self.file_obj = FileFactory()
        self.summarize_url = reverse('api-file-summarize', kwargs={'file_id': self.file_obj.id})
    
    @patch('files.views.AIService')
    @patch('os.path.exists', return_value=True)
    def test_summarize_file_success_operations_user(self, mock_exists, mock_ai_service):
        """Test successful file summarization by operations user"""
        mock_ai_instance = mock_ai_service.return_value
        mock_ai_instance.generate_file_summary.return_value = "This is a test summary."
        
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.summarize_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('file_id', response.data)
        self.assertIn('filename', response.data)
        self.assertIn('summary', response.data)
        self.assertEqual(response.data['summary'], "This is a test summary.")
        
        # Verify AI service was called
        mock_ai_instance.generate_file_summary.assert_called_once()
    
    @patch('files.views.AIService')
    @patch('os.path.exists', return_value=True)
    def test_summarize_file_success_client_user(self, mock_exists, mock_ai_service):
        """Test successful file summarization by client user"""
        mock_ai_instance = mock_ai_service.return_value
        mock_ai_instance.generate_file_summary.return_value = "This is a test summary."
        
        self.create_and_authenticate_client_user()
        
        response = self.client.get(self.summarize_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_summarize_file_unauthenticated(self):
        """Test file summarization denied for unauthenticated user"""
        response = self.client.get(self.summarize_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_summarize_file_nonexistent(self):
        """Test file summarization for nonexistent file"""
        self.create_and_authenticate_operations_user()
        
        invalid_url = reverse('api-file-summarize', kwargs={'file_id': 99999})
        response = self.client.get(invalid_url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    
    @patch('os.path.exists', return_value=False)
    def test_summarize_file_not_found_on_server(self, mock_exists):
        """Test file summarization when file not found on server"""
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.summarize_url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('error', response.data)
        self.assertIn('File not found on server', response.data['error'])
    
    @patch('files.views.AIService')
    @patch('os.path.exists', return_value=True)
    def test_summarize_file_ai_service_error(self, mock_exists, mock_ai_service):
        """Test file summarization with AI service error"""
        mock_ai_instance = mock_ai_service.return_value
        mock_ai_instance.generate_file_summary.side_effect = Exception("AI Error")
        
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.summarize_url)
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn('Something went wrong', response.data['error'])
    
    @patch('files.views.AIService')
    @patch('os.path.exists', return_value=True)
    def test_summarize_file_value_error(self, mock_exists, mock_ai_service):
        """Test file summarization with configuration error"""
        mock_ai_instance = mock_ai_service.return_value
        mock_ai_instance.generate_file_summary.side_effect = ValueError("Config Error")
        
        self.create_and_authenticate_operations_user()
        
        response = self.client.get(self.summarize_url)
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn('AI service configuration error', response.data['error'])


@pytest.mark.integration
class FileWorkflowTests(BaseAPITestCase, AuthenticatedTestMixin):
    """Integration tests for complete file workflows"""
    
    def test_complete_file_upload_download_workflow(self):
        """Test complete workflow: upload -> get download link -> download"""
        # Step 1: Authenticate as operations user and upload file
        ops_user = self.create_and_authenticate_operations_user()
        
        file_data = SimpleUploadedFile(
            "test.docx",
            b"test document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Test Document', 'file': file_data},
            format='multipart'
        )
        
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)
        file_id = upload_response.data['id']
        
        # Step 2: Get download link
        download_link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_id})
        )
        
        self.assertEqual(download_link_response.status_code, status.HTTP_200_OK)
        download_link = download_link_response.data['download_link']
        
        # Extract token from download link
        token = download_link.split('/download/')[-1].rstrip('/')
        
        # Step 3: Download file (no authentication required)
        self.unauthenticate()
        
        with patch('builtins.open', mock_open(read_data=b"file content")), \
             patch('os.path.exists', return_value=True):
            
            download_response = self.client.get(
                reverse('api-file-download', kwargs={'token': token})
            )
            
            self.assertEqual(download_response.status_code, status.HTTP_200_OK)
        
        # Verify FileAccess was marked as used
        file_access = FileAccess.objects.filter(file_id=file_id).first()
        self.assertTrue(file_access.is_used)
    
    @patch('files.views.AIService')
    @patch('os.path.exists', return_value=True)
    def test_complete_file_upload_summarize_workflow(self, mock_exists, mock_ai_service):
        """Test complete workflow: upload -> summarize"""
        mock_ai_instance = mock_ai_service.return_value
        mock_ai_instance.generate_file_summary.return_value = "AI generated summary"
        
        # Step 1: Upload file
        ops_user = self.create_and_authenticate_operations_user()
        
        file_data = SimpleUploadedFile(
            "test.docx",
            b"test document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Test Document', 'file': file_data},
            format='multipart'
        )
        
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)
        file_id = upload_response.data['id']
        
        # Step 2: Summarize file
        summarize_response = self.client.get(
            reverse('api-file-summarize', kwargs={'file_id': file_id})
        )
        
        self.assertEqual(summarize_response.status_code, status.HTTP_200_OK)
        self.assertEqual(summarize_response.data['summary'], "AI generated summary")
        self.assertEqual(summarize_response.data['file_id'], file_id)
    
    def test_client_user_cannot_upload_but_can_access_files(self):
        """Test that client users cannot upload but can list and download files"""
        # Create a file uploaded by operations user
        ops_user = OperationsUserFactory()
        file_obj = FileFactory(uploaded_by=ops_user, title="Operations File")
        
        # Authenticate as client user
        client_user = self.create_and_authenticate_client_user()
        
        # Should not be able to upload
        file_data = SimpleUploadedFile("test.docx", b"content", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Client Upload', 'file': file_data},
            format='multipart'
        )
        self.assertEqual(upload_response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Should be able to list files
        list_response = self.client.get(reverse('api-file-list'))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data), 1)
        
        # Should be able to get download link
        download_link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_obj.id})
        )
        self.assertEqual(download_link_response.status_code, status.HTTP_200_OK)
