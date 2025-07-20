import pytest
from unittest.mock import patch, mock_open, MagicMock
from django.test import TestCase, override_settings
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
import tempfile
import os
import base64
from datetime import datetime

from core.encryption import (
    get_encryption_key, encrypt_url_token, decrypt_url_token,
    generate_access_token, get_token_expiry
)
from core.ai_service import AIService
from core.permissions import IsOperationsUser, IsClientUser, IsFileOwner
from core.validators import validate_file_extension
from tests.base import BaseTestCase, BaseAPITestCase
from tests.factories import OperationsUserFactory, ClientUserFactory, FileFactory

User = get_user_model()


@pytest.mark.unit
class EncryptionServiceTests(BaseTestCase):
    """Test suite for encryption utilities"""
    
    def test_get_encryption_key_from_settings(self):
        """Test getting encryption key from Django settings"""
        test_key = base64.urlsafe_b64encode(os.urandom(32))
        
        with override_settings(ENCRYPTION_KEY=test_key):
            key = get_encryption_key()
            self.assertEqual(key, test_key)
    
    def test_get_encryption_key_string_conversion(self):
        """Test encryption key string to bytes conversion"""
        test_key_str = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        
        with override_settings(ENCRYPTION_KEY=test_key_str):
            key = get_encryption_key()
            self.assertIsInstance(key, bytes)
            self.assertEqual(key, test_key_str.encode())
    
    @patch('builtins.print')
    def test_get_encryption_key_generates_temporary(self, mock_print):
        """Test temporary key generation when none is set"""
        with override_settings(ENCRYPTION_KEY=None):
            key = get_encryption_key()
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), 44)  # Base64 encoded 32-byte key
            mock_print.assert_called_with("WARNING: Using temporary encryption key. Set ENCRYPTION_KEY in settings.")
    
    def test_encrypt_decrypt_round_trip(self):
        """Test encryption and decryption round trip"""
        original_token = "test-token-12345"
        
        encrypted = encrypt_url_token(original_token)
        self.assertNotEqual(encrypted, original_token)
        self.assertIsInstance(encrypted, str)
        
        decrypted = decrypt_url_token(encrypted)
        self.assertEqual(decrypted, original_token)
    
    def test_decrypt_invalid_token(self):
        """Test decryption of invalid token"""
        invalid_token = "invalid-base64-token"
        result = decrypt_url_token(invalid_token)
        self.assertIsNone(result)
    
    def test_generate_access_token(self):
        """Test access token generation"""
        token = generate_access_token()
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 36)  # UUID4 string length
    
    def test_get_token_expiry(self):
        """Test token expiry calculation"""
        from django.utils import timezone
        from datetime import timedelta
        
        expiry = get_token_expiry()
        now = timezone.now()
        expected_expiry = now + timedelta(hours=24)
        
        # Allow 1 second difference for test execution time
        self.assertAlmostEqual(
            expiry.timestamp(),
            expected_expiry.timestamp(),
            delta=1
        )


@pytest.mark.unit
class AIServiceTests(BaseTestCase):
    """Test suite for AI service functionality"""
    
    def setUp(self):
        super().setUp()
        self.ai_service = AIService()
    
    def test_init_demo_mode_no_api_key(self):
        """Test AI service initialization in demo mode"""
        with override_settings(GEMINI_API_KEY='your-gemini-api-key-here'):
            service = AIService()
            self.assertTrue(service.demo_mode)
            self.assertIsNone(service.model)
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_init_with_valid_api_key(self, mock_model, mock_configure):
        """Test AI service initialization with valid API key"""
        with override_settings(GEMINI_API_KEY='valid-api-key'):
            service = AIService()
            self.assertFalse(service.demo_mode)
            mock_configure.assert_called_once_with(api_key='valid-api-key')
            mock_model.assert_called_once_with('gemini-1.5-flash')
    
    @patch('google.generativeai.configure')
    def test_init_api_error_fallback_to_demo(self, mock_configure):
        """Test fallback to demo mode when API initialization fails"""
        mock_configure.side_effect = Exception("API Error")
        
        with override_settings(GEMINI_API_KEY='valid-api-key'):
            service = AIService()
            self.assertTrue(service.demo_mode)
            self.assertIsNone(service.model)
    
    def test_extract_text_file_not_found(self):
        """Test text extraction from non-existent file"""
        with self.assertRaises(FileNotFoundError):
            self.ai_service.extract_text_from_file("/path/to/nonexistent.docx")
    
    def test_extract_text_unsupported_format(self):
        """Test text extraction from unsupported file format"""
        temp_file = self.create_temp_file_path("test.txt", b"test content")
        
        with self.assertRaises(Exception) as context:
            self.ai_service.extract_text_from_file(temp_file)
        
        self.assertIn("Failed to extract text from .txt file", str(context.exception))
    
    @patch('core.ai_service.Document')
    def test_extract_from_docx(self, mock_document):
        """Test DOCX text extraction"""
        # Mock document with paragraphs
        mock_paragraph1 = MagicMock()
        mock_paragraph1.text = "First paragraph"
        mock_paragraph2 = MagicMock()
        mock_paragraph2.text = "Second paragraph"
        mock_paragraph3 = MagicMock()
        mock_paragraph3.text = "   "  # Empty paragraph
        
        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_paragraph1, mock_paragraph2, mock_paragraph3]
        mock_document.return_value = mock_doc
        
        temp_file = self.create_temp_file_path("test.docx", b"test content")
        result = self.ai_service.extract_text_from_file(temp_file)
        
        expected = "First paragraph\nSecond paragraph"
        self.assertEqual(result, expected)
    
    @patch('core.ai_service.openpyxl.load_workbook')
    def test_extract_from_xlsx(self, mock_workbook):
        """Test XLSX text extraction"""
        # Mock workbook with sheets and cells
        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = [
            ("Header1", "Header2", "Header3"),
            ("Row1Col1", "Row1Col2", "Row1Col3"),
            ("Row2Col1", None, "Row2Col3")
        ]
        
        mock_wb = MagicMock()
        mock_wb.sheetnames = ["Sheet1"]
        mock_wb.__getitem__.return_value = mock_sheet
        mock_workbook.return_value = mock_wb
        
        temp_file = self.create_temp_file_path("test.xlsx", b"test content")
        result = self.ai_service.extract_text_from_file(temp_file)
        
        expected_lines = [
            "Sheet: Sheet1",
            "Header1 | Header2 | Header3",
            "Row1Col1 | Row1Col2 | Row1Col3",
            "Row2Col1 | Row2Col3"
        ]
        self.assertEqual(result, "\n".join(expected_lines))
    
    @patch('core.ai_service.Presentation')
    def test_extract_from_pptx(self, mock_presentation):
        """Test PPTX text extraction"""
        # Mock presentation with slides and shapes
        mock_shape1 = MagicMock()
        mock_shape1.text = "Title text"
        mock_shape2 = MagicMock()
        mock_shape2.text = "Content text"
        mock_shape3 = MagicMock()
        mock_shape3.text = "   "  # Empty shape
        
        mock_slide = MagicMock()
        mock_slide.shapes = [mock_shape1, mock_shape2, mock_shape3]
        
        mock_pres = MagicMock()
        mock_pres.slides = [mock_slide]
        mock_presentation.return_value = mock_pres
        
        temp_file = self.create_temp_file_path("test.pptx", b"test content")
        result = self.ai_service.extract_text_from_file(temp_file)
        
        expected = "Slide 1:\nTitle text\nContent text"
        self.assertEqual(result, expected)
    
    def test_truncate_text_within_limit(self):
        """Test text truncation when within limits"""
        text = "Short text"
        result = self.ai_service._truncate_text(text)
        self.assertEqual(result, text)
    
    def test_truncate_text_exceeds_limit(self):
        """Test text truncation when exceeding limits"""
        long_text = "x" * 35000  # Exceeds 30000 character limit
        result = self.ai_service._truncate_text(long_text)
        
        self.assertTrue(len(result) < len(long_text))
        self.assertIn("[Note: Content truncated due to length limits]", result)
    
    def test_summarize_document_empty_text(self):
        """Test document summarization with empty text"""
        result = self.ai_service.summarize_document("")
        self.assertEqual(result, "No text content found in the document.")
    
    def test_summarize_document_demo_mode(self):
        """Test document summarization in demo mode"""
        with override_settings(GEMINI_API_KEY='your-gemini-api-key-here'):
            service = AIService()
            text = "This is a test document with some content."
            result = service.summarize_document(text)
            
            self.assertIn("Demo AI Summary", result)
            self.assertIn("Configure GEMINI_API_KEY for full AI analysis", result)
    
    @patch('google.generativeai.GenerativeModel')
    def test_summarize_document_api_success(self, mock_model_class):
        """Test successful document summarization with API"""
        mock_response = MagicMock()
        mock_response.text = "This is an AI-generated summary."
        
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_model_class.return_value = mock_model
        
        with override_settings(GEMINI_API_KEY='valid-api-key'):
            service = AIService()
            service.model = mock_model
            service.demo_mode = False
            
            text = "Test document content"
            result = service.summarize_document(text)
            
            self.assertEqual(result, "This is an AI-generated summary.")
            mock_model.generate_content.assert_called_once()
    
    @patch('google.generativeai.GenerativeModel')
    def test_summarize_document_quota_error(self, mock_model_class):
        """Test document summarization with quota error"""
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("quota exceeded")
        mock_model_class.return_value = mock_model
        
        with override_settings(GEMINI_API_KEY='valid-api-key'):
            service = AIService()
            service.model = mock_model
            service.demo_mode = False
            
            text = "Test document content"
            result = service.summarize_document(text)
            
            self.assertIn("Rate Limited", result)
            self.assertIn("rate limit exceeded", result)
    
    @patch('google.generativeai.GenerativeModel')
    def test_summarize_document_other_error(self, mock_model_class):
        """Test document summarization with other API errors"""
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("Other API error")
        mock_model_class.return_value = mock_model
        
        with override_settings(GEMINI_API_KEY='valid-api-key'):
            service = AIService()
            service.model = mock_model
            service.demo_mode = False
            
            text = "Test document content"
            
            with self.assertRaises(Exception) as context:
                service.summarize_document(text)
            
            self.assertIn("AI summarization failed", str(context.exception))
    
    @patch.object(AIService, 'extract_text_from_file')
    @patch.object(AIService, 'summarize_document')
    def test_generate_file_summary_success(self, mock_summarize, mock_extract):
        """Test successful file summary generation"""
        mock_extract.return_value = "Extracted text content"
        mock_summarize.return_value = "Generated summary"
        
        result = self.ai_service.generate_file_summary("/path/to/file.docx")
        
        self.assertEqual(result, "Generated summary")
        mock_extract.assert_called_once_with("/path/to/file.docx")
        mock_summarize.assert_called_once_with("Extracted text content")
    
    @patch.object(AIService, 'extract_text_from_file')
    def test_generate_file_summary_extraction_error(self, mock_extract):
        """Test file summary generation with extraction error"""
        mock_extract.side_effect = Exception("Extraction failed")
        
        with self.assertRaises(Exception) as context:
            self.ai_service.generate_file_summary("/path/to/file.docx")
        
        self.assertEqual(str(context.exception), "Extraction failed")


@pytest.mark.unit
class PermissionsTests(BaseAPITestCase):
    """Test suite for custom permissions"""
    
    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        self.operations_user = OperationsUserFactory()
        self.client_user = ClientUserFactory()
    
    def test_is_operations_user_permission_success(self):
        """Test IsOperationsUser permission with operations user"""
        permission = IsOperationsUser()
        request = self.factory.get('/')
        request.user = self.operations_user
        
        result = permission.has_permission(request, None)
        self.assertTrue(result)
    
    def test_is_operations_user_permission_denied_client_user(self):
        """Test IsOperationsUser permission denied for client user"""
        permission = IsOperationsUser()
        request = self.factory.get('/')
        request.user = self.client_user
        
        result = permission.has_permission(request, None)
        self.assertFalse(result)
    
    def test_is_operations_user_permission_denied_unauthenticated(self):
        """Test IsOperationsUser permission denied for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        permission = IsOperationsUser()
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        result = permission.has_permission(request, None)
        self.assertFalse(result)
    
    def test_is_client_user_permission_success(self):
        """Test IsClientUser permission with client user"""
        permission = IsClientUser()
        request = self.factory.get('/')
        request.user = self.client_user
        
        result = permission.has_permission(request, None)
        self.assertTrue(result)
    
    def test_is_client_user_permission_denied_operations_user(self):
        """Test IsClientUser permission denied for operations user"""
        permission = IsClientUser()
        request = self.factory.get('/')
        request.user = self.operations_user
        
        result = permission.has_permission(request, None)
        self.assertFalse(result)
    
    def test_is_file_owner_permission_success(self):
        """Test IsFileOwner permission with file owner"""
        file_obj = FileFactory(uploaded_by=self.operations_user)
        permission = IsFileOwner()
        request = self.factory.get('/')
        request.user = self.operations_user
        
        result = permission.has_object_permission(request, None, file_obj)
        self.assertTrue(result)
    
    def test_is_file_owner_permission_denied_different_user(self):
        """Test IsFileOwner permission denied for different user"""
        file_obj = FileFactory(uploaded_by=self.operations_user)
        other_user = OperationsUserFactory()
        permission = IsFileOwner()
        request = self.factory.get('/')
        request.user = other_user
        
        result = permission.has_object_permission(request, None, file_obj)
        self.assertFalse(result)


@pytest.mark.unit
class ValidatorsTests(BaseTestCase):
    """Test suite for file validators"""
    
    def test_validate_file_extension_valid_docx(self):
        """Test file extension validation with valid DOCX file"""
        file_mock = MagicMock()
        file_mock.name = "document.docx"
        
        # Should not raise an exception
        validate_file_extension(file_mock)
    
    def test_validate_file_extension_valid_xlsx(self):
        """Test file extension validation with valid XLSX file"""
        file_mock = MagicMock()
        file_mock.name = "spreadsheet.xlsx"
        
        # Should not raise an exception
        validate_file_extension(file_mock)
    
    def test_validate_file_extension_valid_pptx(self):
        """Test file extension validation with valid PPTX file"""
        file_mock = MagicMock()
        file_mock.name = "presentation.pptx"
        
        # Should not raise an exception
        validate_file_extension(file_mock)
    
    def test_validate_file_extension_case_insensitive(self):
        """Test file extension validation is case insensitive"""
        file_mock = MagicMock()
        file_mock.name = "document.DOCX"
        
        # Should not raise an exception
        validate_file_extension(file_mock)
    
    def test_validate_file_extension_invalid_txt(self):
        """Test file extension validation with invalid TXT file"""
        file_mock = MagicMock()
        file_mock.name = "document.txt"
        
        with self.assertRaises(ValidationError) as context:
            validate_file_extension(file_mock)
        
        self.assertIn("Unsupported file extension", str(context.exception))
    
    def test_validate_file_extension_invalid_pdf(self):
        """Test file extension validation with invalid PDF file"""
        file_mock = MagicMock()
        file_mock.name = "document.pdf"
        
        with self.assertRaises(ValidationError) as context:
            validate_file_extension(file_mock)
        
        self.assertIn("Only pptx, docx, and xlsx files are allowed", str(context.exception))
    
    def test_validate_file_extension_no_extension(self):
        """Test file extension validation with file having no extension"""
        file_mock = MagicMock()
        file_mock.name = "filename_without_extension"
        
        with self.assertRaises(ValidationError) as context:
            validate_file_extension(file_mock)
        
        self.assertIn("Unsupported file extension", str(context.exception))
