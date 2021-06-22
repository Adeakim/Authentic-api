from logging import raiseExceptions
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import generics,status
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from django.conf import settings
from .models import User,generate_otp
from .serializers import GenerateOTPSerializer,SetNewPasswordSerializer, LoginSerializers,VerifyOTPSerializer,UserSerializer,ForgetPasswordSerializer
from .utils import Util
from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,smart_bytes,force_str,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util


class RegisterView(generics.ListCreateAPIView):
    permission_classes=(permissions.AllowAny,)
    serializer_class = UserSerializer
    queryset=User.objects.all
    def post(self,request):
        user=request.data
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True) 
        
        serializer.save() 
        email = request.data.get('email')
        
        code = generate_otp()
        user = get_user_model().objects.get(email=email)
        user.otp_code=code
        user.save()
        token=code
        email_body=f'Hi{user.username}\n Please copy the code below to verify your email \n {token}'
        data={'email_body':email_body,'to_email':[user.email],'email_subject':'Verify your email'}
        Util.send_email(data)
        user_data=serializer.data
        user=User.objects.get(email=user_data['email'])
        token=RefreshToken.for_user(user).access_token
        user.save()
       
        return Response(user_data,status=status.HTTP_201_CREATED)
    

class VerifyOTPView(generics.CreateAPIView):
    serializer_class=VerifyOTPSerializer
    
    def get(self,request):
        return Response({'message':"please enter the cerification code hat was sent to your mail"})
    
    def post(self,request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            print('\n', serializer.data.get('otp_code'))
        
        token = serializer.data.get('otp_code')
       
        try:
            
            user=User.objects.get(otp_code=token) 
           
            if not user.verification:
                user.verification=True
                user.otp_code=token
                user.save()
                return Response({'email':'Succesfully Activated'},status=status.HTTP_200_OK)
        except:
            return Response({'error':'Account not verified. Please provide a valid code'},
                            status=status.HTTP_400_BAD_REQUEST)
    
    
    
    
    
class GenerateOTPVIew(generics.ListCreateAPIView):
    permission_classes=(permissions.IsAuthenticated,)
    queryset=User.objects.all()
    serializer_class=GenerateOTPSerializer
    
    def post(self,request):
        try:
            email = request.data.get('email')
        
            code = generate_otp()
            user = get_user_model().objects.get(email=email)
            user.otp_code=code
            user.save()
            token=code
            email_body=f'Hi{user.username}\n Please copy the code below to verify your email \n {token}'
            data={'email_body':email_body,'to_email':[user.email],'email_subject':'Verify your email'}
            Util.send_email(data)
            return Response({"otp_code":code},status=status.HTTP_201_CREATED)
        except :
            return Response({"message":"User does not exist"}, status=404)
    

class VerifyOTPView(generics.CreateAPIView):
    permission_classes=(permissions.IsAuthenticated,)
    serializer_class=VerifyOTPSerializer
    def get(self,request):
        return Response({'message':"please enter the cerification code hat was sent to your mail"})
    def post(self,request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            print('\n', serializer.data.get('otp_code'))
        
        token = serializer.data.get('otp_code')
        try:
            
            user=User.objects.get(otp_code=token)
           
           
            if not user.verification:
                user.verification=True
                user.otp_code=token
                user.save()
                return Response({'email':'Succesfully Activated'},status=status.HTTP_200_OK)
        except:
            return Response({'error':'Account not verified. Please provide a valid code'},
                            status=status.HTTP_400_BAD_REQUEST)  
   
 
class LoginViews(generics.CreateAPIView):
    queryset=User.objects.all()
    serializer_class=LoginSerializers
    

class ForgetPasswordAPI(generics.GenericAPIView):
    
    serializer_class=ForgetPasswordSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        
        email=request.data['email']
        if User.objects.filter(email=email).exists():
                user=User.objects.get(email=email)
                uidb64=urlsafe_base64_encode(smart_bytes(user.id))
                token=PasswordResetTokenGenerator().make_token(user)
                current_site=get_current_site(request=request).domain
                relativeLink=reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
                absurl='http://'+current_site+relativeLink
                email_body='Hello \n Use link below to reset your password \n'+absurl
                data={'email_body':email_body,'to_email':[user.email],'email_subject':'Reset your password',}
                Util.send_email(data)
        return Response({'success':'we have sent a link to reset your password'},status=status.HTTP_200_OK)
        
class PasswordTOkenCheckAPI(generics.GenericAPIView):
    
    def get(self,request,uidb64,token):
        try:
            id=smart_bytes(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'error':'Token is ampared with, Please request a new one'},status=status.HTTP_401_UNAUTHORIZED)
            
            return Response({'success':True,'message':"Verified",'uidb64':uidb64,'token':token},status=status.HTTP_200_OK)
            
            
                
        except DjangoUnicodeDecodeError:
              return Response({'error':'Token is not valid'},status=status.HTTP_401_UNAUTHORIZED)
          
class SetNewPassword(generics.GenericAPIView):
    serializer_class=SetNewPasswordSerializer
    
    def patch(self,request):
        serializer=self.serializer_class(data=request.data)
        
        serializer.is_valid(raise_exception=True)
        return Response({'success':True,'message':'Password reset success'},status=status.HTTP_201_CREATED)