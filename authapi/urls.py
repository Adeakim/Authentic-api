from django.urls import path
from.views import RegisterView,VerifyOTPView,GenerateOTPVIew,SetNewPassword,PasswordTOkenCheckAPI,ForgetPasswordAPI

urlpatterns=[
   
    path('register/', RegisterView.as_view(), name='register'),
    path('generate-otp/', GenerateOTPVIew.as_view(), name='generate_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('forgot-password',ForgetPasswordAPI.as_view(),name='forget-password'),
    path('password-reset/<uidb64>/<token>/',PasswordTOkenCheckAPI.as_view(),name='password-reset-confirm'),
    # path('set-new-password/',SetNewPassword.as_view(),name='set-new-password'),
    path('passwords/reset/',SetNewPassword.as_view(),name='set-new-password')
    
    
    
]

