"""authz URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.http.response import HttpResponse
from .views import *

admin.autodiscover()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('oauth2/token/', TokenView.as_view()),
    path('oauth2/introspect/', IntrospectView.as_view()),
    path('oauth2/refresh/', RefreshView.as_view()),
    path('status/', lambda r: HttpResponse())
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
