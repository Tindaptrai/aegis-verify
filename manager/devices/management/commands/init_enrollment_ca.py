from django.core.management.base import BaseCommand, CommandError
from devices.issuer import initialize_issuer, IssuerUnavailable


class Command(BaseCommand):
    help = "Explicitly initialize the configured private enrollment CA without replacing existing state."

    def handle(self, *args, **options):
        try:
            initialize_issuer()
        except IssuerUnavailable:
            raise CommandError("Enrollment issuer unavailable; inspect configured paths and permissions.") from None
        self.stdout.write("Enrollment issuer ready.")
