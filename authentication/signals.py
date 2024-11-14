from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, School, Bursar


@receiver(post_save, sender=User)
def create_school_for_school_owner(sender, instance, created, **kwargs):
    if created and instance.role == 'SCHOOL_OWNER':
        if not hasattr(instance, 'school'):
            School.objects.create(name=instance.username, owner=instance)



