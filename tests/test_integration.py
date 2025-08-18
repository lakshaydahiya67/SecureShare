import pytest
from unittest.mock import patch, mock_open
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
import tempfile
import os
from datetime import timedelta

from files.models import File, FileAccess
from core.encryption import encrypt_url_token, decrypt_url_token
from tests.base import BaseAPITestCase, AuthenticatedTestMixin
from tests.factories import OperationsUserFactory, ClientUserFactory, FileFactory

User = get_user_model()


@pytest.mark.integration
class CompleteUserJourneyTests(BaseAPITestCase):
    """Integration tests for complete user journeys through the application"""
    
    @patch('users.views.send_mail')
    def test_complete_client_user_journey(self, mock_send_mail):
        """Test complete client user journey: signup -> verify -> login -> browse files -> download"""
        
        # Step 1: Client user signup
        signup_data = {
            'email': 'client@test.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.CLIENT
        }
        
        signup_response = self.client.post(reverse('api-signup'), signup_data)
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        
        # Get created user
        user = User.objects.get(email='client@test.com')
        self.assertFalse(user.is_email_verified)
        self.assertIsNotNone(user.verification_token)
        
        # Step 2: Email verification
        verify_response = self.client.get(
            reverse('verify-email', kwargs={'token': user.verification_token})
        )
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        
        # Step 3: Login
        login_data = {
            'email': 'client@test.com',
            'password': 'strongpassword123'
        }
        
        login_response = self.client.post(reverse('api-login'), login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertNotIn('token', login_response.data)  # Session auth doesn't return tokens
        
        # Use force_authenticate for subsequent API requests in tests
        self.client.force_authenticate(user=user)
        
        # Step 4: Create a file for testing (as ops user first)
        ops_user = OperationsUserFactory()
        test_file = FileFactory(uploaded_by=ops_user, title="Test Document")
        
        # Step 5: Browse available files
        files_response = self.client.get(reverse('api-file-list'))
        self.assertEqual(files_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(files_response.data), 1)
        self.assertEqual(files_response.data[0]['title'], "Test Document")
        
        # Step 6: Get download link
        download_link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': test_file.id})
        )
        self.assertEqual(download_link_response.status_code, status.HTTP_200_OK)
        download_link = download_link_response.data['download_link']
        
        # Step 7: Download file using the link (no auth required)
        self.client.force_authenticate(user=None)  # Remove authentication
        
        token = download_link.split('/download/')[-1].rstrip('/')
        
        with patch('builtins.open', mock_open(read_data=b"test file content")), \
             patch('os.path.exists', return_value=True):
            
            download_response = self.client.get(
                reverse('api-file-download', kwargs={'token': token})
            )
            self.assertEqual(download_response.status_code, status.HTTP_200_OK)
        
        # Verify email was sent during signup
        mock_send_mail.assert_called_once()
    
    @patch('users.views.send_mail')
    def test_complete_operations_user_journey(self, mock_send_mail):
        """Test complete operations user journey: signup -> verify -> login -> upload -> manage -> summarize"""
        
        # Step 1: Operations user signup
        signup_data = {
            'email': 'ops@test.com',
            'password': 'strongpassword123',
            'password_confirm': 'strongpassword123',
            'user_type': User.UserType.OPERATION
        }
        
        signup_response = self.client.post(reverse('api-signup'), signup_data)
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        
        # Get created user
        user = User.objects.get(email='ops@test.com')
        
        # Step 2: Email verification
        verify_response = self.client.get(
            reverse('verify-email', kwargs={'token': user.verification_token})
        )
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        
        # Step 3: Login
        login_data = {
            'email': 'ops@test.com',
            'password': 'strongpassword123'
        }
        
        login_response = self.client.post(reverse('api-login'), login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertNotIn('token', login_response.data)  # Session auth doesn't return tokens
        
        # Use force_authenticate for subsequent API requests in tests
        self.client.force_authenticate(user=user)
        
        # Step 4: Upload a file
        file_data = SimpleUploadedFile(
            "operations_doc.docx",
            b"operations document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Operations Document', 'file': file_data},
            format='multipart'
        )
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)
        file_id = upload_response.data['id']
        
        # Step 5: List files to verify upload
        files_response = self.client.get(reverse('api-file-list'))
        self.assertEqual(files_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(files_response.data), 1)
        self.assertEqual(files_response.data[0]['title'], "Operations Document")
        
        # Step 6: Generate file summary
        with patch('files.views.AIService') as mock_ai_service, \
             patch('os.path.exists', return_value=True):
            
            mock_ai_instance = mock_ai_service.return_value
            mock_ai_instance.generate_file_summary.return_value = "AI-generated operations summary"
            
            summary_response = self.client.get(
                reverse('api-file-summarize', kwargs={'file_id': file_id})
            )
            self.assertEqual(summary_response.status_code, status.HTTP_200_OK)
            self.assertEqual(summary_response.data['summary'], "AI-generated operations summary")
        
        # Step 7: Generate download link for sharing
        download_link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_id})
        )
        self.assertEqual(download_link_response.status_code, status.HTTP_200_OK)
        self.assertIn('download_link', download_link_response.data)
    
    def test_cross_user_type_interactions(self):
        """Test interactions between different user types"""
        
        # Create operations user and upload a file
        ops_user = OperationsUserFactory()
        self.client.force_authenticate(user=ops_user)
        
        file_data = SimpleUploadedFile(
            "shared_doc.xlsx",
            b"shared document content",
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
        upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Shared Document', 'file': file_data},
            format='multipart'
        )
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)
        file_id = upload_response.data['id']
        
        # Switch to client user
        client_user = ClientUserFactory(is_email_verified=True)
        self.client.force_authenticate(user=client_user)
        
        # Client should be able to see the file in listing
        files_response = self.client.get(reverse('api-file-list'))
        self.assertEqual(files_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(files_response.data), 1)
        
        # Client should be able to get download link
        download_link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_id})
        )
        self.assertEqual(download_link_response.status_code, status.HTTP_200_OK)
        
        # Client should be able to request summary
        with patch('files.views.AIService') as mock_ai_service, \
             patch('os.path.exists', return_value=True):
            
            mock_ai_instance = mock_ai_service.return_value
            mock_ai_instance.generate_file_summary.return_value = "Client-accessible summary"
            
            summary_response = self.client.get(
                reverse('api-file-summarize', kwargs={'file_id': file_id})
            )
            self.assertEqual(summary_response.status_code, status.HTTP_200_OK)
        
        # But client should NOT be able to upload files
        client_file_data = SimpleUploadedFile(
            "client_doc.docx",
            b"client document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        client_upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Client Document', 'file': client_file_data},
            format='multipart'
        )
        self.assertEqual(client_upload_response.status_code, status.HTTP_403_FORBIDDEN)


@pytest.mark.integration
class FileSecurityWorkflowTests(BaseAPITestCase):
    """Integration tests for file security workflows"""
    
    def test_download_token_security_workflow(self):
        """Test the complete security workflow for file download tokens"""
        
        # Setup: Create file and user
        ops_user = OperationsUserFactory()
        file_obj = FileFactory(uploaded_by=ops_user)
        
        self.client.force_authenticate(user=ops_user)
        
        # Step 1: Generate download link
        link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_obj.id})
        )
        self.assertEqual(link_response.status_code, status.HTTP_200_OK)
        download_link = link_response.data['download_link']
        
        # Extract and verify token
        token = download_link.split('/download/')[-1].rstrip('/')
        self.assertIsNotNone(token)
        
        # Verify FileAccess record was created
        file_access = FileAccess.objects.filter(file=file_obj).first()
        self.assertIsNotNone(file_access)
        self.assertFalse(file_access.is_used)
        self.assertTrue(file_access.expires_at > timezone.now())
        
        # Step 2: Use token once (should succeed)
        self.client.force_authenticate(user=None)  # Remove authentication
        
        with patch('builtins.open', mock_open(read_data=b"file content")), \
             patch('os.path.exists', return_value=True):
            
            first_download = self.client.get(
                reverse('api-file-download', kwargs={'token': token})
            )
            self.assertEqual(first_download.status_code, status.HTTP_200_OK)
        
        # Verify token is now marked as used
        file_access.refresh_from_db()
        self.assertTrue(file_access.is_used)
        
        # Step 3: Try to use token again (should fail)
        second_download = self.client.get(
            reverse('api-file-download', kwargs={'token': token})
        )
        self.assertEqual(second_download.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already used', second_download.data['error'])
    
    def test_token_expiration_workflow(self):
        """Test token expiration security workflow"""
        
        # Create an expired file access
        file_obj = FileFactory()
        expired_access = FileAccess.objects.create(
            file=file_obj,
            expires_at=timezone.now() - timedelta(hours=1),
            is_used=False
        )
        
        # Encrypt the expired token
        encrypted_token = encrypt_url_token(str(expired_access.access_token))
        
        # Try to download with expired token
        response = self.client.get(
            reverse('api-file-download', kwargs={'token': encrypted_token})
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('expired', response.data['error'])
        
        # Verify token was not marked as used
        expired_access.refresh_from_db()
        self.assertFalse(expired_access.is_used)
    
    def test_invalid_token_security(self):
        """Test security with various invalid tokens"""
        
        # Test completely invalid token
        invalid_response = self.client.get(
            reverse('api-file-download', kwargs={'token': 'invalid-token'})
        )
        self.assertEqual(invalid_response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test valid encryption but non-existent UUID
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        fake_token = encrypt_url_token(fake_uuid)
        
        fake_response = self.client.get(
            reverse('api-file-download', kwargs={'token': fake_token})
        )
        self.assertEqual(fake_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid download link', fake_response.data['error'])


@pytest.mark.integration
class ErrorHandlingWorkflowTests(BaseAPITestCase):
    """Integration tests for error handling across workflows"""
    
    def test_file_upload_error_recovery(self):
        """Test error handling and recovery in file upload workflow"""
        
        ops_user = OperationsUserFactory()
        self.client.force_authenticate(user=ops_user)
        
        # Test 1: Invalid file type
        invalid_file = SimpleUploadedFile(
            "document.txt",
            b"invalid file content",
            content_type="text/plain"
        )
        
        upload_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Invalid Document', 'file': invalid_file},
            format='multipart'
        )
        self.assertEqual(upload_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('file', upload_response.data)
        
        # Test 2: Missing required fields
        missing_title_response = self.client.post(
            reverse('api-file-upload'),
            {'file': SimpleUploadedFile("test.docx", b"content", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
            format='multipart'
        )
        self.assertEqual(missing_title_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('title', missing_title_response.data)
        
        # Test 3: Successful upload after fixing errors
        valid_file = SimpleUploadedFile(
            "valid_document.docx",
            b"valid document content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
        success_response = self.client.post(
            reverse('api-file-upload'),
            {'title': 'Valid Document', 'file': valid_file},
            format='multipart'
        )
        self.assertEqual(success_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(success_response.data['title'], 'Valid Document')
    
    @patch('files.views.AIService')
    def test_ai_service_error_handling_workflow(self, mock_ai_service):
        """Test AI service error handling across different scenarios"""
        
        file_obj = FileFactory()
        ops_user = OperationsUserFactory()
        self.client.force_authenticate(user=ops_user)
        
        summarize_url = reverse('api-file-summarize', kwargs={'file_id': file_obj.id})
        
        # Test 1: File not found on server
        with patch('os.path.exists', return_value=False):
            response = self.client.get(summarize_url)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            self.assertIn('File not found on server', response.data['error'])
        
        # Test 2: AI service configuration error
        mock_ai_instance = mock_ai_service.return_value
        mock_ai_instance.generate_file_summary.side_effect = ValueError("Config error")
        
        with patch('os.path.exists', return_value=True):
            response = self.client.get(summarize_url)
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertIn('AI service configuration error', response.data['error'])
        
        # Test 3: General AI service error
        mock_ai_instance.generate_file_summary.side_effect = Exception("General error")
        
        with patch('os.path.exists', return_value=True):
            response = self.client.get(summarize_url)
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertIn('Something went wrong', response.data['error'])
        
        # Test 4: Successful summary after fixing configuration
        mock_ai_instance.generate_file_summary.side_effect = None
        mock_ai_instance.generate_file_summary.return_value = "Successful summary"
        
        with patch('os.path.exists', return_value=True):
            response = self.client.get(summarize_url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['summary'], "Successful summary")
    
    def test_authentication_error_workflow(self):
        """Test authentication error handling across different endpoints"""
        
        file_obj = FileFactory()
        
        # Test unauthenticated access to protected endpoints
        protected_endpoints = [
            ('GET', reverse('api-file-list')),
            ('GET', reverse('api-file-download-link', kwargs={'file_id': file_obj.id})),
            ('GET', reverse('api-file-summarize', kwargs={'file_id': file_obj.id})),
            ('POST', reverse('api-file-upload')),
        ]
        
        for method, url in protected_endpoints:
            if method == 'GET':
                response = self.client.get(url)
            else:
                response = self.client.post(url)
            
            self.assertEqual(
                response.status_code, 
                status.HTTP_403_FORBIDDEN,
                f"Expected 403 for {method} {url}, got {response.status_code}"
            )
        
        # Test invalid token
        self.client.force_authenticate(user=None)  # Test with no authentication
        
        response = self.client.get(reverse('api-file-list'))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Test successful access with valid token
        user = OperationsUserFactory()
        # Use session authentication
        self.client.force_authenticate(user=user)
        
        response = self.client.get(reverse('api-file-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)


@pytest.mark.integration
class PerformanceWorkflowTests(BaseAPITestCase):
    """Integration tests for performance-related workflows"""
    
    def test_multiple_file_operations_workflow(self):
        """Test performance with multiple file operations"""
        
        ops_user = OperationsUserFactory()
        self.client.force_authenticate(user=ops_user)
        
        # Upload multiple files
        uploaded_files = []
        for i in range(5):
            file_data = SimpleUploadedFile(
                f"document_{i}.docx",
                f"document {i} content".encode(),
                content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            
            response = self.client.post(
                reverse('api-file-upload'),
                {'title': f'Document {i}', 'file': file_data},
                format='multipart'
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            uploaded_files.append(response.data['id'])
        
        # List all files
        list_response = self.client.get(reverse('api-file-list'))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data), 5)
        
        # Generate download links for all files
        download_links = []
        for file_id in uploaded_files:
            link_response = self.client.get(
                reverse('api-file-download-link', kwargs={'file_id': file_id})
            )
            self.assertEqual(link_response.status_code, status.HTTP_200_OK)
            download_links.append(link_response.data['download_link'])
        
        # Verify all download links work
        self.client.force_authenticate(user=None)  # Remove authentication
        
        for download_link in download_links:
            token = download_link.split('/download/')[-1].rstrip('/')
            
            with patch('builtins.open', mock_open(read_data=b"file content")), \
                 patch('os.path.exists', return_value=True):
                
                download_response = self.client.get(
                    reverse('api-file-download', kwargs={'token': token})
                )
                self.assertEqual(download_response.status_code, status.HTTP_200_OK)
        
        # Verify all FileAccess records are marked as used
        used_count = FileAccess.objects.filter(is_used=True).count()
        self.assertEqual(used_count, 5)
    
    def test_concurrent_access_simulation(self):
        """Test handling of concurrent access patterns"""
        
        # Create a file
        file_obj = FileFactory()
        ops_user = OperationsUserFactory()
        client_user = ClientUserFactory(is_email_verified=True)
        
        # Simulate concurrent access by different users
        # User 1: Operations user generates download link
        self.client.force_authenticate(user=ops_user)
        link_response = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_obj.id})
        )
        self.assertEqual(link_response.status_code, status.HTTP_200_OK)
        
        # User 2: Client user also generates download link
        self.client.force_authenticate(user=client_user)
        link_response2 = self.client.get(
            reverse('api-file-download-link', kwargs={'file_id': file_obj.id})
        )
        self.assertEqual(link_response2.status_code, status.HTTP_200_OK)
        
        # Verify two separate FileAccess records were created
        access_count = FileAccess.objects.filter(file=file_obj).count()
        self.assertEqual(access_count, 2)
        
        # Both tokens should work independently
        token1 = link_response.data['download_link'].split('/download/')[-1].rstrip('/')
        token2 = link_response2.data['download_link'].split('/download/')[-1].rstrip('/')
        
        self.assertNotEqual(token1, token2)
        
        # Remove authentication for downloads
        self.client.force_authenticate(user=None)
        
        with patch('builtins.open', mock_open(read_data=b"file content")), \
             patch('os.path.exists', return_value=True):
            
            # Both downloads should succeed
            response1 = self.client.get(
                reverse('api-file-download', kwargs={'token': token1})
            )
            self.assertEqual(response1.status_code, status.HTTP_200_OK)
            
            response2 = self.client.get(
                reverse('api-file-download', kwargs={'token': token2})
            )
            self.assertEqual(response2.status_code, status.HTTP_200_OK)
        
        # Both should be marked as used
        used_count = FileAccess.objects.filter(file=file_obj, is_used=True).count()
        self.assertEqual(used_count, 2)