import os
import boto3
from django.db import migrations
from django.conf import settings

class Migration(migrations.Migration):
    dependencies = [
        ('authz', '0001_initial'),
    ]

    def generate_superuser(apps, schema_editor):
        from django.contrib.auth.models import User
        
        ssm = boto3.client('ssm')
        username = ssm.get_parameter(Name=settings.ADMIN_USERNAME, WithDecryption=True)['Parameter']['Value']
        email = settings.ADMIN_EMAIL
        password = ssm.get_parameter(Name=settings.ADMIN_PASSWORD, WithDecryption=True)['Parameter']['Value']

        superuser = User.objects.create_superuser(
            username=username,
            email=email,
            password=password)

        superuser.save()

    operations = [
        migrations.RunPython(generate_superuser),
    ]