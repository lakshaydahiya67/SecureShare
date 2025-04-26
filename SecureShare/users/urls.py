from django.urls import path
from . import views

urlpatterns = [
    # REST API endpoints only - no template views here
    path('signup/', views.SignupView.as_view(), name='api-signup'),
    path('login/', views.LoginView.as_view(), name='api-login'),
    path('verify/<str:token>/', views.VerifyEmailView.as_view(), name='verify-email'),
]