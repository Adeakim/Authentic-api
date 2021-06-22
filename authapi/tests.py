import pyotp
import datetime
from django.urls import reverse

from rest_framework.test import APITestCase


class TestSetup(APITestCase):
    def setUp(self):
        self.resetpassword_url=reverse('set-new-password')
        return super().setUp()

    user_data={
        'email':'email@email.com',
        'password':'testing321',
        'otp_code': ''
    }


    def test_reset_password(self):
        self.client.put(self.resetpassword_url,self.user_data)
        
    
    def tearDown(self):
        return super().tearDown()
        