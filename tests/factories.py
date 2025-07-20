import factory
import factory.fuzzy
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from files.models import File, FileAccess
import tempfile
import os
import uuid
from datetime import timedelta

User = get_user_model()


class UserFactory(factory.django.DjangoModelFactory):
    """Factory for creating User instances"""
    
    class Meta:
        model = User
    
    email = factory.Sequence(lambda n: f"user{n}@test.com")
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    is_active = True
    is_email_verified = True
    user_type = User.UserType.CLIENT
    
    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        if not create:
            return
        
        password = extracted or 'testpass123'
        self.set_password(password)
        self.save()


class OperationsUserFactory(UserFactory):
    """Factory for creating Operations User instances"""
    
    user_type = User.UserType.OPERATION
    email = factory.Sequence(lambda n: f"ops{n}@test.com")


class ClientUserFactory(UserFactory):
    """Factory for creating Client User instances"""
    
    user_type = User.UserType.CLIENT
    email = factory.Sequence(lambda n: f"client{n}@test.com")


class UnverifiedUserFactory(UserFactory):
    """Factory for creating unverified User instances"""
    
    is_email_verified = False
    verification_token = factory.LazyFunction(lambda: str(uuid.uuid4()))


class FileFactory(factory.django.DjangoModelFactory):
    """Factory for creating File instances"""
    
    class Meta:
        model = File
    
    title = factory.Faker('sentence', nb_words=3)
    uploaded_by = factory.SubFactory(OperationsUserFactory)
    uploaded_at = factory.LazyFunction(timezone.now)
    
    @factory.lazy_attribute
    def file(self):
        """Create a temporary file for testing"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
        temp_file.write(b"Test document content")
        temp_file.close()
        
        # Create SimpleUploadedFile from the temp file
        with open(temp_file.name, 'rb') as f:
            content = f.read()
        
        # Clean up the temp file
        os.unlink(temp_file.name)
        
        return SimpleUploadedFile(
            name="test.docx",
            content=content,
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )


class DocxFileFactory(FileFactory):
    """Factory for creating DOCX File instances"""
    
    title = factory.Faker('sentence', nb_words=3, variable_nb_words=False)
    
    @factory.lazy_attribute
    def file(self):
        return SimpleUploadedFile(
            name="test.docx",
            content=b"Test DOCX content",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )


class XlsxFileFactory(FileFactory):
    """Factory for creating XLSX File instances"""
    
    title = factory.Faker('sentence', nb_words=3, variable_nb_words=False)
    
    @factory.lazy_attribute
    def file(self):
        return SimpleUploadedFile(
            name="test.xlsx",
            content=b"Test XLSX content",
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )


class PptxFileFactory(FileFactory):
    """Factory for creating PPTX File instances"""
    
    title = factory.Faker('sentence', nb_words=3, variable_nb_words=False)
    
    @factory.lazy_attribute
    def file(self):
        return SimpleUploadedFile(
            name="test.pptx",
            content=b"Test PPTX content",
            content_type="application/vnd.openxmlformats-officedocument.presentationml.presentation"
        )


class FileAccessFactory(factory.django.DjangoModelFactory):
    """Factory for creating FileAccess instances"""
    
    class Meta:
        model = FileAccess
    
    file = factory.SubFactory(FileFactory)
    access_token = factory.LazyFunction(uuid.uuid4)
    created_at = factory.LazyFunction(timezone.now)
    expires_at = factory.LazyFunction(lambda: timezone.now() + timedelta(hours=24))
    is_used = False


class ExpiredFileAccessFactory(FileAccessFactory):
    """Factory for creating expired FileAccess instances"""
    
    expires_at = factory.LazyFunction(lambda: timezone.now() - timedelta(hours=1))


class UsedFileAccessFactory(FileAccessFactory):
    """Factory for creating used FileAccess instances"""
    
    is_used = True


class InvalidFileTypeFactory(FileFactory):
    """Factory for creating files with invalid extensions for testing validation"""
    
    @factory.lazy_attribute
    def file(self):
        return SimpleUploadedFile(
            name="test.txt",
            content=b"Test invalid file content",
            content_type="text/plain"
        )