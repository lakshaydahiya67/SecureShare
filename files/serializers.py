from rest_framework import serializers
from .models import File, FileAccess
from .validators import validate_file_extension
from django.contrib.auth import get_user_model

User = get_user_model()

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'title', 'file', 'uploaded_by', 'uploaded_at']
        read_only_fields = ['uploaded_by', 'uploaded_at']
    
    def validate_file(self, value):
        # Use our custom validator
        validate_file_extension(value)
        return value
    
    def create(self, validated_data):
        # Set the uploaded_by field to the current user
        validated_data['uploaded_by'] = self.context['request'].user
        return super().create(validated_data)

class FileListSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'title', 'uploaded_at']

class FileDownloadSerializer(serializers.Serializer):
    download_link = serializers.CharField()
    message = serializers.CharField()