
import os
from django.apps import AppConfig
from django.conf import settings

class GmailtoolConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'gmailtool'

    def ready(self):
        """Starts the scheduler when the Django app is ready."""
        # Avoid starting scheduler during migrations or in autoreloader's child process
        run_main = os.environ.get('RUN_MAIN', None) == 'true'
        if settings.DEBUG and run_main or not settings.DEBUG:
             # Import scheduler here to avoid AppRegistryNotReady errors
             from . import scheduler
             print("Starting APScheduler...")
             scheduler.start()
        else:
             print("Skipping scheduler start (likely autoreloader child process).")