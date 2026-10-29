from django.core.management.base import BaseCommand, CommandError
from connections.services import cleanup_expired
from connections.storage import StorageError


class Command(BaseCommand):
    help = 'Remove expired unpublished connection drafts; preserve every registered source.'

    def handle(self, **options):
        try:
            cleanup_expired()
        except StorageError:
            raise CommandError('storage_unavailable') from None
        self.stdout.write('Expired unpublished connection drafts cleaned.')
