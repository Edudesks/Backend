from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    school_name = serializers.CharField(max_length=255)
    confirm_password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    default_error_messages = {
        'username': 'This school name is already taken.',
    }

    class Meta:
        model = User
        fields = ['email', 'school_name', 'password','confirm_password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        school_name = attrs.get('school_name', '')
        password = attrs.get('password', '')
        confirm_password = attrs.get('confirm_password', '')
        
        if password != confirm_password:
            raise serializers.ValidationError({"password": "Passwords do not match."})

       
        if User.objects.filter(username=school_name).exists():
            raise serializers.ValidationError({'school_name': self.default_error_messages['username']})

        return attrs

    def create(self, validated_data):
        validated_data['username'] = validated_data['school_name']
        validated_data.pop('school_name')
        validated_data.pop('confirm_password')
        return User.objects.create_user(**validated_data)

    

class EmailVerificationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=555)
    otp = serializers.CharField(max_length=4)

    class Meta:
        model = User  
        fields = ['email', 'otp']


class RequestOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=555)

    class Meta:  
        fields = ['email']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    school_name = serializers.CharField(source='username', max_length=255, min_length=3, read_only=True)
    tokens = serializers.SerializerMethodField(read_only=True)
    
    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        return {
            'access': user.tokens()['access'],
            'refresh': user.tokens()['refresh'],
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'school_name', 'tokens']
    
    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        print(email )
        print(password)
        user = authenticate(username=email, password=password)
        print(user)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        tokens = user.tokens()

        return {
            'email': user.email,
            'school_name': user.username, 
            'tokens': tokens
        
        }


class InviteBursarSerializer(serializers.Serializer): 
    email = serializers.EmailField(max_length=255, min_length=3)
    
    class Meta:
        fields = ['email']



class ResetPasswordEmailRequsetSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length = 2)

    redirect_url = serializers.CharField(max_length = 500, required=False)

    class Meta:
        fields = ['email']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields =['password','token','uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id  = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id = id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed('The reset link invalid', 401)
            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs) 
    

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')        