"""Keep technical Admin authority while guarding complete account transactions."""
from django.contrib import admin
from django.contrib.admin.utils import unquote
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm, AdminUserCreationForm
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpResponse

from .errors import AccountError
from .models import AuthAudit
from .permissions import CAPABILITIES
from .services import authority_mutation, record_user_mutation, user_snapshot, validate_product_password


class ProductPasswordValidation:
    def validate_password_for_user(self, user, password_field_name="password2", **kwargs):
        super().validate_password_for_user(user, password_field_name=password_field_name, **kwargs)
        password = self.cleaned_data.get(password_field_name)
        if not user.is_staff and not user.is_superuser and self.cleaned_data.get("set_usable_password", True) and password:
            try:
                validate_product_password(password)
            except AccountError:
                self.add_error(password_field_name, ValidationError("invalid_password"))


class GuardedPasswordForm(ProductPasswordValidation, AdminPasswordChangeForm):
    pass


class GuardedCreationForm(ProductPasswordValidation, AdminUserCreationForm):
    pass


class AuthorityAdminMixin:
    def has_delete_permission(self, request, obj=None):
        return False

    def delete_view(self, request, object_id, extra_context=None):
        raise PermissionDenied

    def delete_model(self, request, obj):
        raise PermissionDenied

    def delete_queryset(self, request, queryset):
        raise PermissionDenied

    def _guard_post(self, request, operation):
        # Django queues success messages and may rotate the current password
        # session before returning. Neither may survive a rejected transaction.
        queued_messages = list(request._messages._queued_messages)
        session_data = dict(request.session)
        session_key = request.session.session_key
        try:
            with authority_mutation(actor=request.user):
                request.user = get_user_model().objects.get(pk=request.user.pk)
                if not request.user.is_staff:
                    raise PermissionDenied
                return operation()
        except AccountError as error:
            request._messages._queued_messages = queued_messages
            request.session.clear()
            request.session.update(session_data)
            request.session._session_key = session_key
            return HttpResponse(error.code, status=error.status, content_type="text/plain")

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        operation = lambda: super(AuthorityAdminMixin, self).changeform_view(request, object_id, form_url, extra_context)
        return self._guard_post(request, operation) if request.method == "POST" else operation()


class GuardedUserAdmin(AuthorityAdminMixin, UserAdmin):
    add_form = GuardedCreationForm
    change_password_form = GuardedPasswordForm

    def save_model(self, request, obj, form, change):
        before = user_snapshot(get_user_model().objects.get(pk=obj.pk)) if change else {}
        super().save_model(request, obj, form, change)
        request._aegis_user_before = before

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        record_user_mutation(actor=request.user, user=form.instance,
                             before=request._aegis_user_before,
                             action="user_updated" if change else "user_created")

    def user_change_password(self, request, id, form_url=""):
        def operation():
            user = self.get_object(request, unquote(id))
            before = user_snapshot(user) if user else None
            response = super(GuardedUserAdmin, self).user_change_password(request, id, form_url)
            if response.status_code == 302 and before is not None:
                user.refresh_from_db()
                # Conflicting form submissions also redirect without a save.
                if request.POST.get("usable_password") != "false" or "unset-password" in request.POST:
                    record_user_mutation(actor=request.user, user=user, before=before, action="password_reset")
            return response
        return self._guard_post(request, operation) if request.method == "POST" else operation()


def group_snapshot(group):
    return {"group_name": group.name, "capabilities": sorted(group.permissions.filter(
        content_type__app_label="accounts", content_type__model="accountsecurity", codename__in=CAPABILITIES
    ).values_list("codename", flat=True))}


class GuardedGroupAdmin(AuthorityAdminMixin, GroupAdmin):
    def save_model(self, request, obj, form, change):
        before = group_snapshot(Group.objects.get(pk=obj.pk)) if change else {}
        super().save_model(request, obj, form, change)
        request._aegis_group_before = before

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        AuthAudit.objects.create(actor_id=request.user.pk, actor_username=request.user.username,
                                 action="group_updated" if change else "group_created",
                                 before=request._aegis_group_before, after=group_snapshot(form.instance))


admin.site.unregister(get_user_model())
admin.site.unregister(Group)
admin.site.register(get_user_model(), GuardedUserAdmin)
admin.site.register(Group, GuardedGroupAdmin)
