from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.http import FileResponse
from django.conf import settings
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import File, FileAccess
from .serializers import FileSerializer, FileListSerializer, FileDownloadSerializer
from core.permissions import IsOperationsUser, IsClientUser
from core.encryption import encrypt_url_token, decrypt_url_token, get_token_expiry

def upload_view(request):
    """Render the file upload template"""
    return render(request, 'files/upload.html')

def list_view(request):
    """Render the file list template"""
    return render(request, 'files/list.html')

def verify_email_view(request, token):
    """User-friendly verification endpoint"""
    try:
        user = User.objects.get(verification_token=token)
        if not user.is_email_verified:
            user.is_email_verified = True
            user.verification_token = None  # Clear the token after use
            user.save()
            return render(request, 'users/verification.html', {
                'success': True
            })
        else:
            return render(request, 'users/verification.html', {
                'success': False,
                'message': 'Email was already verified or token is invalid.'
            })
    except User.DoesNotExist:
        return render(request, 'users/verification.html', {
            'success': False,
            'message': 'Invalid verification token. Please check the URL or request a new verification email.'
        })

class FileUploadView(generics.CreateAPIView):
    """
    Upload a file - only Operations users can upload files
    """
    serializer_class = FileSerializer
    permission_classes = [IsOperationsUser]
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        return context

class FileListView(generics.ListAPIView):
    """
    List all files - allow any authenticated user
    """
    serializer_class = FileListSerializer
    permission_classes = [permissions.IsAuthenticated]  # Allow any authenticated user
    
    def get_queryset(self):
        user = self.request.user
        if user.is_operations_user:
            # Operations users can see all files
            return File.objects.all().order_by('-uploaded_at')
        else:
            # Client users only see files that are available to them
            return File.objects.all().order_by('-uploaded_at')

class FileDownloadLinkView(APIView):
    """
    Get a secure download link for a file
    """
    permission_classes = [permissions.IsAuthenticated] 
    
    def get(self, request, file_id):
        file = get_object_or_404(File, id=file_id)
        
        # Create a file access record with expiry
        file_access = FileAccess.objects.create(
            file=file,
            expires_at=get_token_expiry()
        )
        
        # Generate encrypted download URL
        download_token = encrypt_url_token(str(file_access.access_token))
        download_url = f"{request.scheme}://{request.get_host()}/api/files/download/{download_token}/"
        
        serializer = FileDownloadSerializer({
            'download_link': download_url,
            'message': 'success'
        })
        
        return Response(serializer.data)

class FileDownloadView(APIView):
    """
    Download a file using a secure token
    """
    permission_classes = [permissions.AllowAny]  # Changed from IsClientUser
    
    def get(self, request, token):
        # Decrypt the token
        decrypted_token = decrypt_url_token(token)
        if not decrypted_token:
            return Response(
                {"error": "Invalid or expired download link"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the file access
        try:
            file_access = FileAccess.objects.get(access_token=decrypted_token)
        except (FileAccess.DoesNotExist, ValueError):
            return Response(
                {"error": "Invalid download link"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if the access is expired or already used
        if file_access.expires_at < timezone.now() or file_access.is_used:
            return Response(
                {"error": "Download link expired or already used"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Mark the access as used
        file_access.is_used = True
        file_access.save()
        
        # Return the file
        file_path = file_access.file.file.path
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{file_access.file.filename}"'
        return response
