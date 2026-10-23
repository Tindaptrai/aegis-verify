"""Native Admin own-password form backed by the shared account transaction."""
from django.contrib.admin import AdminSite
from django.contrib.admin.forms import AdminPasswordChangeForm
from django.contrib.auth import get_user_model
from django.contrib.auth.views import PasswordChangeView
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from .errors import AccountError
from .services import authority_mutation, change_own_password
from .sessions import validate_human_session


class GuardedOwnPasswordView(PasswordChangeView):
    def post(self, request, *args, **kwargs):
        # Admin's entry permission check and AuthenticationMiddleware may have
        # read the user before a competing technical write. Lock before either
        # the fresh authority check or PasswordChangeForm validation.
        try:
            with authority_mutation(actor=request.user):
                if not validate_human_session(request):
                    raise AccountError("unauthenticated", 401)
                request.user = get_user_model().objects.get(pk=request.user.pk)
                if not request.user.is_staff:
                    raise PermissionDenied
                return super().post(request, *args, **kwargs)
        except AccountError as error:
            return HttpResponse(error.code, status=error.status, content_type="text/plain")

    def form_valid(self, form):
        try:
            # Never call the default form.save(): it saves a full User and
            # rotates a Django session without our generation/deadline markers.
            # The shared service checks final policy before refreshing only the
            # current session, while this outer transaction still holds the lock.
            change_own_password(request=self.request, current_password=form.cleaned_data["old_password"],
                                new_password=form.cleaned_data["new_password1"])
        except AccountError as error:
            if error.status != 400:
                raise
            form.add_error(None, error.code)
            return self.form_invalid(form)
        return HttpResponseRedirect(self.get_success_url())


class GuardedAdminSite(AdminSite):
    def password_change(self, request, extra_context=None):
        # Retain the native form, template, namespace and success URL.
        defaults = {
            "form_class": AdminPasswordChangeForm,
            "success_url": reverse("admin:password_change_done", current_app=self.name),
            "extra_context": {**self.each_context(request), **(extra_context or {})},
        }
        if self.password_change_template is not None:
            defaults["template_name"] = self.password_change_template
        request.current_app = self.name
        return GuardedOwnPasswordView.as_view(**defaults)(request)
