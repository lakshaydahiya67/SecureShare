from django.shortcuts import render, redirect
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.conf import settings
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth import get_user_model

from .serializers import UserSerializer, SignupSerializer, LoginSerializer

User = get_user_model()

def login_view(request):
    return render(request, 'users/login.html')

def signup_view(request):
    return render(request, 'users/signup.html')

def verify_email_view(request, token):
    """User-friendly verification endpoint"""
    try:
        user = User.objects.get(verification_token=token)
        if not user.is_email_verified:
            user.is_email_verified = True
            user.verification_token = None  # Clear the token after use
            user.save()
            return render(request, 'emails/verify_email.html', {  # Changed path
                'success': True
            })
        else:
            return render(request, 'emails/verify_email.html', {  # Changed path
                'success': False,
                'message': 'Email was already verified or token is invalid.'
            })
    except User.DoesNotExist:
        return render(request, 'emails/verify_email.html', {  # Changed path
            'success': False,
            'message': 'Invalid verification token. Please check the URL or request a new verification email.'
        })

class SignupView(generics.CreateAPIView):
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate verification token
        token = get_random_string(64)
        user.verification_token = token
        user.save()
        
        # Send verification email
        verification_url = f"{request.scheme}://{request.get_host()}/verify-email/{token}/"
        send_mail(
            'Verify your email',
            f'Please verify your email by clicking this link: {verification_url}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        
        # Create an encrypted URL for the response
        from core.encryption import encrypt_url_token
        encrypted_url = encrypt_url_token(token)
        
        # Modified message to inform about development mode
        if response.ok:
            return Response({
                'message': 'User created successfully',
                'debug_mode': settings.DEBUG,
                'user': {
                    'email': user.email,
                    'user_type': user.user_type
                }
            }, status=status.HTTP_201_CREATED)

class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        # For API requests (if needed in the future)
        if request.accepted_renderer.format == 'json':
            return self._verify_api(request, token)
            
        # For browser requests (HTML response)
        return self._verify_html(request, token)
    
    def _verify_api(self, request, token):
        """Handle API verification requests (JSON response)"""
        user = get_object_or_404(User, verification_token=token)
        if not user.is_email_verified:
            user.is_email_verified = True
            user.verification_token = None  # Clear the token after use
            user.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
        return Response({"message": "Email already verified or invalid token."}, status=status.HTTP_400_BAD_REQUEST)
    
    def _verify_html(self, request, token):
        """Handle browser verification requests (HTML response)"""
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

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )
        
        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.is_email_verified and user.user_type == User.UserType.CLIENT:
            return Response({"error": "Email not verified"}, status=status.HTTP_401_UNAUTHORIZED)
        
        token, _ = Token.objects.get_or_create(user=user)
        
        return Response({
            "token": token.key,
            "user": UserSerializer(user).data
        })
