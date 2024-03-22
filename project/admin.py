from django.contrib import admin
from .models import User, Fichier, IntrusionDetectionLog

admin.site.register(User)
admin.site.register(Fichier)
admin.site.register(IntrusionDetectionLog)
