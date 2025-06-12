from django.contrib import admin
from .models import File, FileAccess

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ('title', 'uploaded_by', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('title', 'uploaded_by__email')

@admin.register(FileAccess)
class FileAccessAdmin(admin.ModelAdmin):
    list_display = ('file', 'created_at', 'expires_at', 'is_used')
    list_filter = ('is_used', 'created_at', 'expires_at')
    search_fields = ('file__title',)
