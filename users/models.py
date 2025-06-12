from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', User.UserType.OPERATION)

        return self.create_user(email, password, **extra_fields)
    
class User(AbstractUser):
    class UserType(models.TextChoices):
        OPERATION = 'OPS', _('Operation User')
        CLIENT = 'CLIENT', _('Client User')
    
    username = None
    email = models.EmailField(_('email address'), unique=True)
    user_type = models.CharField(
        max_length=10,
        choices=UserType.choices,
        default=UserType.CLIENT
    )
    is_email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
    
    @property
    def is_operations_user(self):
        return self.user_type == self.UserType.OPERATION
    
    @property
    def is_client_user(self):
        return self.user_type == self.UserType.CLIENT