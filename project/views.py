from rest_framework import generics, permissions, status
from rest_framework_jwt.settings import api_settings
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer,UserLoginSerializer
from django.core.exceptions import ObjectDoesNotExist
User = get_user_model()
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
from rest_framework import viewsets
from .models import Fichier, IntrusionDetectionLog
from .serializers import FichierSerializer, IntrusionDetectionLogSerializer
from scapy.all import sniff, IP, TCP
from rest_framework.response import Response

class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
class UserLoginView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data.get('user')

        # Générer le token et renvoyer avec la catégorie correspondante
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({'access_token': access_token}, status=status.HTTP_200_OK)


class FichierViewSet(viewsets.ModelViewSet):
    queryset = Fichier.objects.all()
    serializer_class = FichierSerializer

    def create(self, request, *args, **kwargs):
        fichier_data = request.data
        intrusion_type, description = self.detect_file_intrusion(fichier_data['fichier'])
        if intrusion_type and description:
            return Response({'error': 'Fichier malveillant détecté'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            fichier_serializer = self.get_serializer(data=fichier_data)
            if fichier_serializer.is_valid():
                fichier_serializer.save()
                return Response(fichier_serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(fichier_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def detect_file_intrusion(file):
        # Utilisation de Scapy pour analyser le fichier et détecter les intrusions
        packets = sniff(offline=file, count=100)
        for packet in packets:
            intrusion_type, description = IntrusionDetectionLog.detect_intrusion(packet)
            if intrusion_type and description:
                return intrusion_type, description
        return None, None
class IntrusionDetectionLogViewSet(viewsets.ModelViewSet):
    queryset = IntrusionDetectionLog.objects.all()
    serializer_class = IntrusionDetectionLogSerializer