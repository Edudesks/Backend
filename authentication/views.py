from datetime import timedelta
import os
from django.http import HttpResponseRedirect
from django.utils import timezone
import random
from django.conf import settings
from dotenv import load_dotenv
from rest_framework import generics
from .renderers import UserRender
from django.utils.crypto import get_random_string
from .serializers import LogoutSerializer, RegisterSerializer,EmailVerificationSerializer, RequestOtpSerializer, LoginSerializer,InviteBursarSerializer, ResetPasswordEmailRequsetSerializer, SetNewPasswordSerializer
# ResetPasswordEmailRequsetSerializer,SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework import status
# from rest_framework_simplejwt.tokens import RefreshToken
from .models import User,Bursar,School
from .utils import Util
from .permissions import IsAuthenticatedCustom
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode


load_dotenv()


class CustomRedirect(HttpResponseRedirect):
    allowed_schemes=[os.environ.get('APP_SCHEME'),'http','https']

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = (UserRender,)

   
    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        print(user.username)
        # Generate and save OTP
        otp = random.randint(1000, 9999)
        user.otp_code = otp
        user.otp_created_at = timezone.now()
        user.save()
        print(otp)
        email_body = f"Hi {user.username}, your OTP for email verification is {otp}."
        data = {
            'email_body': email_body,
            'to_email': user.email,
            'email_subject': "Verify your email"
        }
        Util.send_email(data)
        
        return Response(
                    {
                        "message": "Account created",
                        "school_name": user.username,
                        "email": user.email,
                        'Role': user.role,
                    },
                    status=status.HTTP_201_CREATED
                )

class VerifyOtpView(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer
    OTP_EXPIRY_MINUTES = 5  # Set OTP validity duration

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']

        try:
            user = User.objects.get(email=email)

            # Check if OTP has expired
            if user.otp_created_at and timezone.now() > user.otp_created_at + timedelta(minutes=self.OTP_EXPIRY_MINUTES):
                return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if OTP matches
            if user.otp_code == otp:
                user.is_verified = True
                user.otp_code = None 
                user.otp_created_at = None
                user.save()
                return Response({'message': 'Email successfully verified'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        

class RequestOtpView(generics.GenericAPIView):
    RESEND_COOLDOWN_SECONDS = 60  # Adjust cooldown period as needed
    serializer_class = RequestOtpSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)

            # Check if user is already verified
            if user.is_verified:
                return Response({'error': 'User is already verified'}, status=status.HTTP_403_FORBIDDEN)

            # Check if user is in cooldown period
            if user.otp_created_at and timezone.now() < user.otp_created_at + timedelta(seconds=self.RESEND_COOLDOWN_SECONDS):
                return Response({'error': 'Please wait before requesting a new OTP'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Generate and save a new OTP
            new_otp = random.randint(1000, 9999)
            user.otp_code = new_otp
            user.otp_created_at = timezone.now()
            user.save()

            # Send the OTP email
            email_body = f"Hi {user.username}, your new OTP for email verification is {new_otp}."
            data = {
                'email_body': email_body,
                'to_email': user.email,
                'email_subject': "Resend OTP - Verify your email"
            }
            Util.send_email(data)

            return Response({'message': 'A new OTP has been sent to your email'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

    
class LoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    renderer_classes = (UserRender,)
    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
    

class InviteBursarView(generics.GenericAPIView):
    serializer_class = InviteBursarSerializer
    permission_classes = [IsAuthenticatedCustom]

    def post(self, request):
        # Ensure the authenticated user is a school owner
        if request.user.role != 'SCHOOL_OWNER':
            return Response({"error": "Only school owners can invite bursars"}, status=status.HTTP_403_FORBIDDEN)

        bursar_email = request.data.get("email")
        if not bursar_email:
            return Response({"error": "Bursar email is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a user with the same email already exists
        if User.objects.filter(email=bursar_email).exists():
            return Response({"error": "A user with this email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a random password and create the user
        random_password = get_random_string(length=8)
        user = User.objects.create_user(
            username=bursar_email,
            email=bursar_email,
            password=random_password,
            role='BURSAR'
        )
        school_name = request.user.username
        print(school_name)
        try:
            school = School.objects.get(name=school_name)
            
            Bursar.objects.create(user=user, school=school)
        except School.DoesNotExist:
            # Handle the case where no matching school is found
            print(f"No school found with the name '{school_name}' for Bursar creation.")

        # Send the invitation email
        email_body = f"Hi, you've been added as a bursar to {request.user.username}. Your login details are:\nEmail: {bursar_email}\nPassword: {random_password}."
        data = {
            'email_body': email_body,
            'to_email': bursar_email,
            'email_subject': "Invitation as a bursar on EDUDESKS",
        }
        try:
            Util.send_email(data)
            return Response({"message": "Bursar invited successfully"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": "Failed to send invitation email. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequsetSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        email = request.data['email']
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email = email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relativeLink = reverse('password-reset-confirm',kwargs={'uidb64': uidb64, 'token':token })
            absurl = 'http://'+current_site+relativeLink
            redirect_url= request.data.get('redirect_url', '')    
            email_body = 'hello, \n use link bellow to reset your password \n' + absurl+"?redirect_url="+redirect_url
            data = {'email_body':email_body, 'to_email':user.email, 'email_subject':"Reset your password"}
            Util.send_email(data)       
        return Response({"success": "we have sent you the link to reset your password"}, status=status.HTTP_200_OK)

class PasswordTokenCheckApiView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self,request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        return Response({'success':True, 'message':'Password reset success', },status=status.HTTP_200_OK)

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    # permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'message':'You have logged out successfully'},status=status.HTTP_204_NO_CONTENT)