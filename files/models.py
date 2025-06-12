from django.db import models
from django.conf import settings
import uuid
import os

def get_file_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('uploads/', filename)

class File(models.Model):
    ALLOWED_EXTENTIONS = ['pptx', 'docx', 'xlsx']

    title = models.CharField(max_length=255)
    file = models.FileField(upload_to=get_file_path)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='uploaded_files'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    
    @property
    def extention(self):
        return self.file.name.split('.')[-1]
    
    @property
    def filename(self):
        return os.path.basename(self.file.name)
    
class FileAccess(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='accesses')
    access_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"Access for {self.file.title}"