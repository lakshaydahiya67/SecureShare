from rest_framework import permissions

class IsOperationsUser(permissions.BasePermission):
    """
    Permission to only allow operations users to perform an action.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_operations_user

class IsClientUser(permissions.BasePermission):
    """
    Permission to only allow client users to perform an action.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_client_user

class IsFileOwner(permissions.BasePermission):
    """
    Permission to only allow owners of a file to access it.
    """
    def has_object_permission(self, request, view, obj):
        return obj.uploaded_by == request.user