# gmailtool/scheduler.py

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from django_apscheduler.jobstores import DjangoJobStore, register_events, register_job
from django.conf import settings

logger = logging.getLogger(__name__)
scheduler = None

def start():
    """Starts the APScheduler."""
    global scheduler
    if scheduler and scheduler.running:
        logger.info("Scheduler already running.")
        return scheduler

    # Using MemoryJobStore as configured in settings.py
    # If you switch to DjangoJobStore in settings, it will be used automatically
    scheduler = BackgroundScheduler(timezone=settings.TIME_ZONE)
    # Uncomment below if you switch settings.py to use DjangoJobStore
    # scheduler.add_jobstore(DjangoJobStore(), "default")

    # It's often good practice to register shutdown events
    register_events(scheduler)

    try:
        scheduler.start()
        logger.info("Scheduler started successfully.")
        # Optional: Print existing jobs on start for debugging
        # try:
        #    print("Existing jobs:")
        #    for job in scheduler.get_jobs():
        #        print(f"  Job ID: {job.id}, Next run: {job.next_run_time}")
        # except Exception as e:
        #    print(f"Error fetching jobs: {e}")

    except KeyboardInterrupt:
        logger.info("Scheduler stopping...")
        scheduler.shutdown()
        logger.info("Scheduler shut down successfully.")
    except Exception as e:
        logger.error(f"Error starting scheduler: {e}")
        if scheduler and scheduler.running:
             scheduler.shutdown() # Ensure shutdown on error

    return scheduler

def get_scheduler():
    """Returns the running scheduler instance."""
    global scheduler
    if not scheduler or not scheduler.running:
        # Attempt to start if not running (might happen in some development server setups)
        return start()
    return scheduler