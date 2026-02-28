from django.shortcuts import render
from rest_framework import status
from rest_framework.generics import UpdateAPIView, GenericAPIView
from rest_framework.response import Response
from .models import CustomUser
from .serializers import SignUpSerializer, UserUpdateSerializer, UserProfileSerializer
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.generics import  UpdateAPIView

class SignUpView(APIView):
    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        response = {
            'status': status.HTTP_201_CREATED,
            'message': user.username
        }
        return Response(response)


class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = self.request.data.get('username')
        password = self.request.data.get('password')

        user = authenticate(username=username, password=password)

        if not user:
            raise ValidationError({'message': 'Username yoki parol notogri'})

        refresh_token = RefreshToken.for_user(user)

        response = {
            'status': status.HTTP_201_CREATED,
            'message': 'Siz ruxatdan otdingiz',
            'refresh': str(refresh_token),
            'access': str(refresh_token.access_token)
        }
        return Response(response)



class LogoutView(APIView):
    permission_classes = (IsAuthenticated, )


    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response(
                    {
                        'status': status.HTTP_204_NO_CONTENT,
                        'message': 'Siz refresh token yubormadingiz'
                    },status=status.HTTP_200_OK
                )

        except Exception:
            return Response(
                {
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'yuborilmadi yoki xato'
                }
            )


class UserUpdateView(UpdateAPIView):
    permission_classes = (IsAuthenticated, )
    queryset = CustomUser.objects.all()
    serializer_class = UserUpdateSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        return Response(
        {
            "status": status.HTTP_200_OK,
            "message": "malumot ozgartirildi",
        }
        )

    def partial_update(self, request, *args, **kwargs):
        return Response(
        {
            "status": status.HTTP_200_OK,
            "message": "malumotlar qisman ozgartirildi",
        }
        )

class UserProfileView(GenericAPIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = UserProfileSerializer
    queryset = CustomUser

    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)

        data = {
            'status': status.HTTP_200_OK,
            'user': serializer.data
        }

        return Response(data)


class LoginRefreshView(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        refresh_token = self.request.data.get('refresh_token')

        refresh = RefreshToken(refresh_token)

        response = {
            'status': status.HTTP_201_CREATED,
            'message': 'Siz ruxatdan otdingiz',
            'access': str(refresh.access_token)
        }
        return Response(response)


