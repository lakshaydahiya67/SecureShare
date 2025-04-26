from django.shortcuts import render, redirect
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required

def home_view(request):
    """Homepage view that redirects based on authentication status and user type"""
    if request.user.is_authenticated:
        if request.user.is_operations_user:
            return redirect('file-upload')  # Redirect ops users to upload page
        elif request.user.is_client_user:
            return redirect('file-list')    # Redirect client users to files list
        else:
            return redirect('admin:index')  # Redirect admin users to admin
    else:
        # Show landing page for unauthenticated users
        return render(request, 'home.html')

@login_required
def logout_view(request):
    logout(request)
    return redirect('home')