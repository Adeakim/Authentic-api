from django.db import models
import math, random
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin



def generate_otp():
    corpus= "0123456789"
    otp_code= ""        
    size=5
    length = len(corpus) 
    for i in range(size) : 
        otp_code+= corpus[math.floor(random.random() * length)]        
    return str(otp_code)

 
class UserManager(BaseUserManager):
    
    def create_user(self,username,email,password=None):
        
        if username is None:
            raise TypeError("Users should have username")
        if email is None:
            raise TypeError("Users should have email")
        
        user=self.model(username=username,email=self.normalize_email(email))
        user.set_password(password)
        user.save(using=self.db)
        
        return user
    
    def create_superuser(self,username,email,password=None):
        
        if username is None:
            raise TypeError("Users should have username")
        if email is None:
            raise TypeError("Users should have email")
        
        user=self.model(username=username,email=self.normalize_email(email))
        user.is_superuser=True
        user.is_staff=True
        user.set_password(password)
        user.save(using=self.db)
        
        return user
        
class User(AbstractBaseUser,PermissionsMixin):
    username=models.CharField(max_length=30,unique=True)
    first_name=models.CharField(max_length=200)
    last_name=models.CharField(max_length=200)
    email=models.EmailField(max_length=255,unique=True)
    otp_code=models.CharField(max_length=5, null=True, blank=True)
    verification=models.BooleanField(default=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    is_active=models.BooleanField(default=True)
    is_superuser=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    password=models.CharField(max_length=200)
    token=models.CharField(max_length=255,null=True, blank=True)
     
    objects=UserManager()
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username']
    
    def __str__(self):
        return self.email
    
    
    def tokens(self):
        refresh=RefreshToken.for_user(self)
        return{
            'refresh':str(refresh),
            'access':str(refresh)
        }

