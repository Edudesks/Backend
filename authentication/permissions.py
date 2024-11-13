from rest_framework.permissions import BasePermission
from rest_framework.exceptions import AuthenticationFailed

class IsAuthenticatedCustom(BasePermission):
    """
    Custom permission to check if the user is authenticated.
    Allows access if authenticated; otherwise, returns a specific error.
    """

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            # User is authenticated, allow the action
            return True
        else:
            # Raise an AuthenticationFailed error if the user is not authenticated
            raise AuthenticationFailed("You must be logged in to perform this action.")
