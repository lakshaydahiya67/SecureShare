"""
URL configuration for SecureShare project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from core import views as core_views
from users import views as user_views
from files import views as file_views

urlpatterns = [
    # Main pages
    path('', core_views.home_view, name='home'),
    path('logout/', core_views.logout_view, name='logout'),
    
    # User-facing template views
    path('login/', user_views.login_view, name='login'),
    path('signup/', user_views.signup_view, name='signup'),
    path('verify-email/<str:token>/', user_views.verify_email_view, name='verify-email'),
    path('upload/', file_views.upload_view, name='file-upload'),
    path('files/', file_views.list_view, name='file-list'),
    
    # API endpoints
    path('admin/', admin.site.urls),
    path('api/users/', include('users.urls')),
    path('api/files/', include('files.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
