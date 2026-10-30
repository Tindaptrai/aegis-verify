"""Wait for later reviewed activation; never run the registered collection worker."""
import signal
from threading import Event
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections
from connections.worker import RegistryError, waiting_status


class Command(BaseCommand):
    help = 'Observe managed candidate metadata; always wait without collection authority.'

    def add_arguments(self, parser):
        parser.add_argument('--once', action='store_true', help='Report waiting state once and exit.')

    def handle(self, *args, **options):
        stopping = Event()
        previous = {}

        def stop(signum, frame):
            stopping.set()

        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, stop)
            last = None
            while not stopping.is_set():
                close_old_connections()
                try:
                    state = waiting_status()
                except RegistryError as error:
                    raise CommandError(str(error)) from None
                if state != last:
                    self.stdout.write(state)
                    self.stdout.flush()
                    last = state
                if options['once']:
                    break
                stopping.wait(5)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
