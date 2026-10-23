from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.db.models import F
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import AccountSecurity


@receiver(pre_save, sender=settings.AUTH_USER_MODEL, dispatch_uid="accounts.observe_password")
def observe_password(sender, instance, raw=False, using="default", update_fields=None, **kwargs):
    instance._aegis_password_changed = False
    if raw or instance._state.adding or (update_fields is not None and "password" not in update_fields):
        return
    old_password = sender.objects.using(using).filter(pk=instance.pk).values_list("password", flat=True).first()
    instance._aegis_password_changed = old_password is not None and old_password != instance.password


@receiver(post_save, sender=settings.AUTH_USER_MODEL, dispatch_uid="accounts.create_security")
def create_account_security(sender, instance, created, raw=False, using="default", **kwargs):
    if created and not raw:
        AccountSecurity.objects.using(using).create(user_id=instance.pk)
    elif not raw and getattr(instance, "_aegis_password_changed", False):
        AccountSecurity.objects.using(using).filter(user_id=instance.pk).update(generation=F("generation") + 1)


@receiver(user_logged_in, dispatch_uid="accounts.stamp_human_login")
def stamp_human_login(sender, request, user, **kwargs):
    from .sessions import stamp_login
    stamp_login(request, user)
