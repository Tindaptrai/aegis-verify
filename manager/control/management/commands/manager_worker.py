"""Independent bounded collection worker; Ctrl+C stops after current collection."""
import signal
import time
from django.core.management.base import BaseCommand, CommandError
from control.collection import load_connection
from control.worker import process_one, validate_output_root, worker_lock, recover_interrupted


class Command(BaseCommand):
    help = 'Collect and evaluate approved, completed jobs using private Wazuh configuration.'

    def add_arguments(self, parser):
        parser.add_argument('--config')
        parser.add_argument('--output-root', required=True)
        parser.add_argument('--once', action='store_true')
        parser.add_argument('--settle-seconds', type=int, default=30)
        parser.add_argument('--recover-interrupted', action='store_true',
            help='Explicitly mark interrupted collections failed, then exit without source requests.')

    def handle(self, *args, **options):
        if not 0 <= options['settle_seconds'] <= 300:
            raise CommandError('invalid_settle_seconds')
        try:
            root = validate_output_root(options['output_root'])
            if options['recover_interrupted']:
                count = recover_interrupted(root)
                self.stdout.write(f'interrupted_collections_marked_failed={count}')
                return
            if not options['config']:
                raise ValueError
            connection = load_connection(options['config'])
        except ValueError as error:
            if str(error) == 'worker_already_running':
                raise CommandError('worker_already_running') from None
            raise CommandError('invalid_private_worker_configuration') from None
        except Exception:
            raise CommandError('invalid_private_worker_configuration') from None
        stopping = False

        def stop(signum, frame):
            nonlocal stopping
            stopping = True

        previous = signal.signal(signal.SIGINT,stop)
        previous_term = signal.signal(signal.SIGTERM,stop)
        try:
            with worker_lock(root):
                while not stopping:
                    try:
                        process_one(connection,root,settle_seconds=options['settle_seconds'])
                    except Exception:
                        raise CommandError('collection_worker_unavailable') from None
                    if options['once'] or stopping:
                        break
                    for _ in range(50):
                        if stopping:
                            break
                        time.sleep(0.1)
        except ValueError:
            raise CommandError('worker_already_running') from None
        finally:
            signal.signal(signal.SIGINT,previous)
            signal.signal(signal.SIGTERM,previous_term)
