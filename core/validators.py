from django.core.exceptions import ValidationError
import os

def validate_file_extension(file):
    ext = os.path.splitext(file.name)[1]  # Get the extension with dot
    valid_extensions = ['.pptx', '.docx', '.xlsx']
    if not ext.lower() in valid_extensions:
        raise ValidationError('Unsupported file extension. Only pptx, docx, and xlsx files are allowed.')