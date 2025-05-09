import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'stayslay.settings')

app = Celery('stayslay')  # Use your project name here.

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'apply-rules-periodically': { # Give it a descriptive name
        'task': 'gmailtool.tasks.apply_auto_delete_rules', # Point to the CORRECT task
        # 'schedule': crontab(minute=0, hour='*/4'),  # Example: Run every 4 hours
        # Or run hourly:
        'schedule': crontab(minute=0, hour='*'),
        # Or run every 30 minutes (adjust frequency based on needs/load)
        # 'schedule': crontab(minute='*/30'),
    },
    # Remove the old 'check_and_schedule_deletion' entry
}