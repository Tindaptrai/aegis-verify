"""Independent bounded collection worker; Ctrl+C stops after current collection."""
import signal
import time
from contextlib import nullcontext
from django.core.management.base import BaseCommand, CommandError
from control.collection import load_connection
from control.worker import process_one, validate_output_root, worker_lock, recover_interrupted


class Command(BaseCommand):
    help = 'Collect and evaluate approved, completed jobs using private Wazuh configuration.'

    def add_arguments(self, parser):
        parser.add_argument('--config')
        parser.add_argument('--execution-connection')
        parser.add_argument('--execution-revision', type=int)
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
            registered = None
            if options.get('execution_connection') is not None:
                if options['config'] or options.get('execution_revision') is None: raise ValueError
                from control.execution_connections import resolve_execution_connection
                from control.execution_models import RegisteredExecutionConnection
                connection, registered_root = resolve_execution_connection(options['execution_connection'],options['execution_revision'])
                if registered_root != root: raise ValueError
                registered = RegisteredExecutionConnection.objects.get(connection_id=options['execution_connection'],revision=options['execution_revision'])
            else:
                if not options['config'] or options.get('execution_revision') is not None: raise ValueError
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
                from control.worker_health import execution_worker_health
                with execution_worker_health(registered) if registered else nullcontext() as health:
                    while not stopping:
                        try:
                            if health is not None and health.stop.is_set(): raise ValueError
                            if registered is None:
                                process_one(connection,root,settle_seconds=options['settle_seconds'])
                            else:
                                # Explicit registration identity is mandatory.
                                # Until Task5 adds the v2 dispatcher kwarg this
                                # raises and stops; no credential-equality fallback.
                                process_one(connection,root,settle_seconds=options['settle_seconds'],execution_connection=registered)
                        except Exception:
                            raise CommandError('collection_worker_unavailable') from None
                        if options['once'] or stopping:
                            break
                        for _ in range(50):
                            if stopping: break
                            time.sleep(0.1)
        except ValueError as error:
            raise CommandError('worker_already_running' if str(error)=='worker_already_running' else 'collection_worker_unavailable') from None
        finally:
            signal.signal(signal.SIGINT,previous)
            signal.signal(signal.SIGTERM,previous_term)
