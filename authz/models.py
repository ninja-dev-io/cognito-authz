import django
from django.db import models
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _


class GlobalPermissionManager(models.Manager):
    use_in_migrations = True

    def get_queryset(self):
        return super(GlobalPermissionManager, self).get_queryset().filter(content_type__model='globalpermission')


class GlobalPermission(Permission):
    """A global permission, not attached to a model"""

    objects = GlobalPermissionManager()

    class Meta:
        proxy = True
        verbose_name = _('Global Permission')
        verbose_name_plural = _('Global Permissions')

    def save(self, *args, **kwargs):
        content_type_kwargs = {'app_label': self._meta.app_label,
                               'model': 'globalpermission'}
        ct, created = ContentType.objects.get_or_create(**content_type_kwargs)
        self.content_type = ct
        super(GlobalPermission, self).save(*args, **kwargs)
