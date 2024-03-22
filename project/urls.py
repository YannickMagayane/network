from django.urls import path, include
from .views import UserRegisterView, UserLoginView, FichierViewSet, IntrusionDetectionLogViewSet, UserViewSet

urlpatterns = [
    path('users/register/', UserRegisterView.as_view(), name='user-register'),
    path('users/login/', UserLoginView.as_view(), name='user-login'),
    path('fichiers/', FichierViewSet.as_view({'get': 'list', 'post': 'create'}), name='fichier-list'),
    path('fichiers/<int:pk>/', FichierViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='fichier-detail'),
    path('intrusion-logs/', IntrusionDetectionLogViewSet.as_view({'get': 'list', 'post': 'create'}), name='intrusion-log-list'),
    path('intrusion-logs/<int:pk>/', IntrusionDetectionLogViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='intrusion-log-detail'),
    path('utilisateurs/', UserViewSet.as_view({'get': 'list', 'post': 'create'}), name='user-list'),
    path('utilisateurs/<int:pk>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-detail'),
]
