from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, role='SCHOOL_OWNER'):
        if username is None:
            raise TypeError("User should have a school name")
        if email is None:
            raise TypeError("User should have a school email")

        user = self.model(username=username, email=self.normalize_email(email), role=role)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError("Superuser should have a password")

        user = self.create_user(username, email, password, role='SCHOOL_OWNER')
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('SCHOOL_OWNER', 'School Owner'),
        ('BURSAR', 'Bursar'),
    )
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='SCHOOL_OWNER')
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)    
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

    def __str__(self):
        return f"{self.email}"

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }        
    

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }        
    
class School(models.Model):
    name = models.CharField(max_length=255, unique=True)
    owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="school")

    def __str__(self):
        return self.name


class Bursar(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="bursar_profile")
    school = models.ForeignKey(School, on_delete=models.CASCADE, related_name="bursars")
    can_send_money = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Bursar"
        verbose_name_plural = "Bursars"

    def __str__(self):
        return f"Bursar {self.user.email} at {self.school.name}"
       