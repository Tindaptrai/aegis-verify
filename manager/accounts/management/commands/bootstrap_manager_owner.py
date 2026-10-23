from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import AccountMutationLock
from accounts.permissions import PRESETS, PRESET_GROUP_NAMES


class Command(BaseCommand):
    help = "Explicitly bootstrap the published aegis/aegis account on a new install."

    def add_arguments(self, parser):
        parser.add_argument("--new-install", action="store_true")

    def handle(self, *args, **options):
        if not options["new_install"]:
            raise CommandError("new_install_required")
        with transaction.atomic():
            try:
                AccountMutationLock.objects.select_for_update().get(pk=1)
            except AccountMutationLock.DoesNotExist:
                raise CommandError("account_presets_not_migrated") from None
            users = get_user_model().objects
            if users.exists():
                return "existing_users_unchanged"
            groups = {group.name: group for group in Group.objects.filter(name__in=PRESET_GROUP_NAMES.values())}
            if set(groups) != set(PRESET_GROUP_NAMES.values()):
                raise CommandError("account_presets_not_migrated")
            for role, name in PRESET_GROUP_NAMES.items():
                expected = {("accounts", "accountsecurity", capability) for capability in PRESETS[role]}
                actual = set(groups[name].permissions.values_list("content_type__app_label", "content_type__model", "codename"))
                if actual != expected:
                    raise CommandError("account_presets_not_migrated")
            # This published initial password is explicitly requested for new installs.
            user = users.create_user("aegis", password="aegis", is_staff=False, is_superuser=False)
            user.groups.add(groups[PRESET_GROUP_NAMES["admin"]])
        return "owner_created"
