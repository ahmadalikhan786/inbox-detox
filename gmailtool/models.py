
# gmailtool/models.py
import logging
from django.db import models
from django.conf import settings # To link to User model
from django.utils import timezone

logger = logging.getLogger(__name__)

# Removed ScheduledSender model
# Removed DeletionRule model


class UserOAuthToken(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="google_oauth_token"
    )
    refresh_token = models.CharField(max_length=512, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"OAuth Token for {self.user.username}"

class ScheduledDeletionRule(models.Model):
    """
    Represents a rule set by a user to automatically delete emails
    from a specific sender older than a certain period (fixed at >1 day here).
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scheduled_deletion_rules",
        help_text="The user who created this rule."
    )
    sender_email_to_delete = models.EmailField(
        help_text="The email address of the sender whose emails should be deleted."
    )
    # days_older_than = models.PositiveIntegerField(default=1) # Hardcoded to 1 day for now
    is_active = models.BooleanField(
        default=True,
        help_text="Is this rule currently active and should be processed?"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_run_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of the last time this rule was processed."
    )
    last_error = models.TextField(
        blank=True,
        null=True,
        help_text="Stores the last error message if processing this rule failed."
    )

    class Meta:
        # Prevent duplicate rules for the same user and sender
        unique_together = ('user', 'sender_email_to_delete')
        ordering = ['user', 'sender_email_to_delete']
        verbose_name = "Scheduled Deletion Rule"
        verbose_name_plural = "Scheduled Deletion Rules"

    def __str__(self):
        status = "active" if self.is_active else "inactive"
        return (f"Rule for {self.user.username}: delete from '{self.sender_email_to_delete}' "
                f"(older than 1 day) - Status: {status}")

class SenderAnalysisResult(models.Model):
    """
    Stores the result and status of a background sender analysis task.
    This helps track the progress and outcome of generating the sender list.
    """
    class StatusChoices(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        PROCESSING = 'PROCESSING', 'Processing'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'

    # Link to the user who requested the analysis
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    # Store the Celery task ID to potentially check its state later
    celery_task_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=StatusChoices.choices,
        default=StatusChoices.PENDING,
        db_index=True
    )
    # Use JSONField to store the dictionary of {sender_email: count}
    # Make sure your database supports JSONField (e.g., PostgreSQL, newer SQLite)
    sender_counts = models.JSONField(null=True, blank=True, default=dict)
    # Store some stats about the run
    total_ids_fetched = models.PositiveIntegerField(default=0)
    total_messages_processed = models.PositiveIntegerField(default=0) # How many detail fetches were attempted/completed
    total_errors_encountered = models.PositiveIntegerField(default=0) # Errors during detail fetch/parsing
    # Store any error message if the task fails
    error_message = models.TextField(null=True, blank=True)
    # Timestamps
    started_at = models.DateTimeField(auto_now_add=True) # When the DB record was created
    task_started_at = models.DateTimeField(null=True, blank=True) # When the Celery task actually started
    updated_at = models.DateTimeField(auto_now=True) # Last modification time
    completed_at = models.DateTimeField(null=True, blank=True) # When the task finished (success or fail)

    def __str__(self):
        return f"Analysis for {self.user.username or self.user.id} ({self.status}) - Task ID: {self.celery_task_id or 'N/A'}"

    def get_sorted_senders(self):
        """Helper to get sorted list from the JSON data."""
        if self.status == self.StatusChoices.COMPLETED and self.sender_counts:
            try:
                # Sort by count (value) descending
                return sorted(self.sender_counts.items(), key=lambda item: item[1], reverse=True)
            except Exception:
                logger.error(f"Error sorting sender_counts for AnalysisResult {self.id}", exc_info=True)
                return [] # Handle potential malformed data
        return []

    @property
    def processing_note(self):
        """Generates the note shown to the user based on status and stats."""
        # This property might be used if you adapt views.py to show results from this model later
        if self.status == SenderAnalysisResult.StatusChoices.COMPLETED:
            completed_time_str = self.completed_at.strftime('%Y-%m-%d %H:%M') if self.completed_at else 'N/A'
            note = f"Analysis completed ({completed_time_str}). "
            success_count = self.total_messages_processed - self.total_errors_encountered
            note += f"Found {len(self.sender_counts or {})} senders from {success_count} successfully processed emails " \
                    f"({self.total_messages_processed} attempts from {self.total_ids_fetched} total IDs found)."
            if self.total_errors_encountered > 0:
                note += f" Encountered {self.total_errors_encountered} errors."
            return note
        elif self.status == SenderAnalysisResult.StatusChoices.FAILED:
            failed_time_str = self.completed_at.strftime('%Y-%m-%d %H:%M') if self.completed_at else 'N/A'
            return f"Analysis failed ({failed_time_str}). Error: {self.error_message or 'Unknown error'}"
        elif self.status == SenderAnalysisResult.StatusChoices.PROCESSING:
            start_time_str = self.task_started_at.strftime('%Y-%m-%d %H:%M') if self.task_started_at else 'N/A'
            return f"Analysis started ({start_time_str}) and is currently processing... Please refresh later."
        else: # Pending
            return "Analysis is pending and should start soon."

    class Meta:
        ordering = ['-started_at'] # Show most recent analysis requests first
        verbose_name = "Sender Analysis Result"
        verbose_name_plural = "Sender Analysis Results"




