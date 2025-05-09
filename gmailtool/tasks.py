
import logging
import time
import re
from datetime import timedelta

from celery import shared_task
from celery.exceptions import MaxRetriesExceededError, Ignore

from django.utils import timezone as django_timezone
from django.conf import settings
from django.contrib.auth import get_user_model

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import BatchHttpRequest

from .models import SenderAnalysisResult, UserOAuthToken, ScheduledDeletionRule

logger = logging.getLogger(__name__)
User = get_user_model()

try:
    from .utils import trash_messages_from_sender
except ImportError:
    logger.warning("Could not import 'trash_messages_from_sender' from .utils. Task 'background_trash_sender' will fail if called.")
    def trash_messages_from_sender(creds_dict, sender): return (0, "Utility function 'trash_messages_from_sender' missing from utils.py")
try:
    from .utils import parse_sender_from_headers
except ImportError:
    logger.warning("Could not import 'parse_sender_from_headers' from .utils. Task 'process_sender_analysis_task' may fail.")
    def parse_sender_from_headers(headers):
        if not headers: return None
        for h in headers:
            if h.get('name','').lower() == 'from':
                match = re.search(r'[\w\.-]+@[\w\.-]+', h.get('value',''))
                if match: return match.group(0).lower()
                break
        return None

ANALYSIS_BATCH_LIMIT = 100
ANALYSIS_MAX_RETRIES_RATE_LIMIT = 5
ANALYSIS_RETRY_DELAY_SECONDS = 60
SCHEDULED_TRASH_BATCH_SIZE = 100
SCHEDULED_LIST_PAGE_SIZE = 500
SCHEDULED_MAX_MESSAGES_PER_RUN = getattr(settings, 'GMAIL_MAX_MESSAGES_PER_SCHEDULED_RULE_RUN', 2000)

def credentials_to_dict(credentials):
    """Converts Google Credentials object to a dictionary."""
    if not credentials: return {}
    return {
        'token': getattr(credentials, 'token', None),
        'refresh_token': getattr(credentials, 'refresh_token', None),
        'token_uri': getattr(credentials, 'token_uri', None),
        'client_id': getattr(credentials, 'client_id', None),
        'client_secret': getattr(credentials, 'client_secret', None),
        'scopes': getattr(credentials, 'scopes', [])
    }


def _get_valid_credentials_for_user(user_id: int) -> Credentials | None:
    """ Helper to retrieve and refresh Google OAuth credentials for a user ID. """
    log_prefix_helper = f"[AUTH_HELPER UserID:{user_id}]"
    try:
        user_token_obj = UserOAuthToken.objects.get(user_id=user_id)
        if not user_token_obj.refresh_token:
            logger.error(f"{log_prefix_helper} No refresh token stored in DB.")
            return None

        logger.debug(f"{log_prefix_helper} Found refresh token in DB: {user_token_obj.refresh_token[:20]}...") # Log partial token

        credentials = Credentials(
            token=None, # Always fetch a new access token
            refresh_token=user_token_obj.refresh_token,
            token_uri=settings.GOOGLE_TOKEN_URI,
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            scopes=settings.GOOGLE_OAUTH2_SCOPES
        )

        # The token object is initially not valid because it lacks an access token.
        # We must attempt a refresh.
        logger.info(f"{log_prefix_helper} Attempting to refresh token.")
        try:
            credentials.refresh(GoogleAuthRequest())
            logger.info(f"{log_prefix_helper} Token refreshed successfully. Access token expires at: {credentials.expiry}")
            # Check if still valid after refresh (it should be)
            if not credentials.valid:
                logger.error(f"{log_prefix_helper} CRITICAL: Token still invalid even after successful-looking refresh call.")
                # This is a strange state, implies an issue with the library or Google's response
                user_token_obj.refresh_token = None; user_token_obj.save() # Invalidate bad token
                ScheduledDeletionRule.objects.filter(user_id=user_id, is_active=True).update(is_active=False, last_error="Token refresh failed validation.")
                return None
            return credentials # Successfully refreshed and validated
        # except RefreshError as e_refresh: # More specific catch for google.auth.exceptions
        except Exception as e_refresh: # Catch any exception during refresh
            # THIS IS THE MOST IMPORTANT LOG TO CHECK
            logger.error(f"{log_prefix_helper} FAILED to refresh token. Error Type: {type(e_refresh).__name__}, Error: {e_refresh}", exc_info=True)
            # The refresh token is likely invalid (e.g., 'invalid_grant'). Invalidate it.
            user_token_obj.refresh_token = None
            user_token_obj.save()
            ScheduledDeletionRule.objects.filter(user_id=user_id, is_active=True).update(
                is_active=False, last_error=f"Auto-deactivated: Google token invalid/revoked."
            )
            logger.warning(f"{log_prefix_helper} Deactivated rules for user_id {user_id} due to token refresh failure.")
            return None # Refresh failed

    except UserOAuthToken.DoesNotExist:
        logger.error(f"{log_prefix_helper} UserOAuthToken record not found in DB.")
        return None
    except AttributeError as e_settings:
         logger.error(f"{log_prefix_helper} Missing Google credential setting in Django settings ({e_settings}). Cannot refresh token.")
         return None
    except Exception as e_outer: # Catch-all for other unexpected errors
        logger.error(f"{log_prefix_helper} Unexpected error getting/refreshing credentials: {e_outer}", exc_info=True)
        return None

# ... (rest of your tasks.py remains the same) ...
def _chunk_list(lst, chunk_size):
    """Yield successive chunk_size-sized chunks from lst."""
    if not lst or chunk_size < 1: return
    for i in range(0, len(lst), chunk_size): yield lst[i:i + chunk_size]

# ============================================
# ---              CELERY TASKS            ---
# ============================================

@shared_task(bind=True, default_retry_delay=60, max_retries=3, name='gmailtool.tasks.background_trash_sender')
def background_trash_sender(self, credentials_dict, sender_email, user_id=None):
    """ Celery task for "Delete Now". Calls utils.trash_messages_from_sender. """
    task_id = self.request.id
    log_prefix = f"[TASK background_trash_sender ID:{task_id} User:{user_id or 'N/A'} Sender:{sender_email}]"
    logger.info(f"{log_prefix} START")
    actual_creds_for_util = None

    try:
        if not credentials_dict or not isinstance(credentials_dict, dict) or not any(credentials_dict.values()):
             logger.error(f"{log_prefix} Invalid or empty credentials_dict received.")
             raise ValueError("Invalid credentials dictionary received.")

        try:
            credentials = Credentials(**credentials_dict)
            if credentials.expired and credentials.refresh_token:
                 logger.info(f"{log_prefix} Credentials expired, attempting refresh.")
                 credentials.refresh(GoogleAuthRequest())
                 logger.info(f"{log_prefix} Credentials refreshed.")
                 actual_creds_for_util = credentials_to_dict(credentials) # Use refreshed dict
            elif not credentials.valid:
                 logger.error(f"{log_prefix} Credentials invalid and cannot refresh.")
                 raise Ignore()
            else:
                 actual_creds_for_util = credentials_dict # Use original dict

        except Exception as cred_error:
             logger.error(f"{log_prefix} Error handling credentials: {cred_error}", exc_info=True)
             if isinstance(cred_error, (HttpError, ConnectionError, TimeoutError)):
                  raise self.retry(exc=cred_error) from cred_error
             else:
                  raise Ignore() from cred_error

        # --- Call the utility function ---
        logger.info(f"{log_prefix} Calling trash_messages_from_sender utility...")
        count, error_msg = trash_messages_from_sender(actual_creds_for_util, sender_email)
        logger.info(f"{log_prefix} Result from util: Count={count}, Error='{error_msg}'")

        # --- Handle result from utility ---
        if error_msg:
            logger.error(f"{log_prefix} Error reported from utility: {error_msg}")
            is_retryable_error = False
            if isinstance(error_msg, str):
                 if "429" in error_msg or "500" in error_msg or "503" in error_msg or "refresh failed" in error_msg:
                     is_retryable_error = True
            if is_retryable_error:
                 logger.warning(f"{log_prefix} Retrying task due to potentially recoverable util error.")
                 raise self.retry(exc=Exception(error_msg))
            else:
                 logger.error(f"{log_prefix} Non-retryable error from utility: {error_msg}")
                 return {'status': 'error', 'message': error_msg, 'count': 0}
        else:
            logger.info(f"{log_prefix} Success reported from utility: Trashed {count} messages.")
            return {'status': 'success', 'message': f'Successfully trashed {count} messages from {sender_email}.', 'count': count}

    except Ignore:
        logger.warning(f"{log_prefix} Task ignored due to unrecoverable error.")
        return {'status': 'ignored', 'message': 'Task aborted due to error.', 'count': 0}
    except MaxRetriesExceededError:
        logger.error(f"{log_prefix} Max retries exceeded.")
        return {'status': 'error', 'message': 'Task failed after maximum retries.', 'count': 0}
    except Exception as exc:
        logger.error(f"{log_prefix} UNEXPECTED EXCEPTION in task wrapper: {exc}", exc_info=True)
        try:
            raise self.retry(exc=exc) from exc
        except MaxRetriesExceededError:
            logger.error(f"{log_prefix} Max retries exceeded after unexpected error.")
            return {'status': 'error', 'message': f'Unexpected task error: {exc} (Max retries exceeded)', 'count': 0}


@shared_task(bind=True, max_retries=3, default_retry_delay=120, name='gmailtool.tasks.process_sender_analysis')
def process_sender_analysis_task(self, user_id, analysis_result_id):
    """ Analyzes inbox for sender counts. Updates SenderAnalysisResult model. """
    task_id = self.request.id
    log_prefix = f"[TASK process_sender_analysis ID:{task_id} User:{user_id} AnalysisID:{analysis_result_id}]"
    logger.info(f"{log_prefix} START")
    analysis_result = None
    processed_detail_count = 0
    total_detail_fetch_errors = 0
    batch_execution_errors = 0

    try:
        try:
            analysis_result = SenderAnalysisResult.objects.get(pk=analysis_result_id, user_id=user_id)
            if analysis_result.status not in [SenderAnalysisResult.StatusChoices.PENDING, SenderAnalysisResult.StatusChoices.FAILED]:
                logger.warning(f"{log_prefix} Analysis status is {analysis_result.status}. Aborting.")
                raise Ignore()
            analysis_result.status = SenderAnalysisResult.StatusChoices.PROCESSING
            analysis_result.celery_task_id = task_id
            analysis_result.task_started_at = django_timezone.now()
            analysis_result.error_message = None
            analysis_result.save(update_fields=['status', 'celery_task_id', 'task_started_at', 'error_message', 'updated_at'])
        except SenderAnalysisResult.DoesNotExist:
            logger.error(f"{log_prefix} AnalysisResult {analysis_result_id} not found.")
            raise Ignore()
        except Ignore: raise
        except Exception as model_exc:
            logger.error(f"{log_prefix} DB Error accessing AnalysisResult {analysis_result_id}: {model_exc}", exc_info=True)
            raise self.retry(exc=model_exc) from model_exc

        credentials = _get_valid_credentials_for_user(user_id)
        if not credentials:
            err_msg = f"Could not retrieve valid credentials for user {user_id}"
            logger.error(f"{log_prefix} {err_msg}")
            analysis_result.status = SenderAnalysisResult.StatusChoices.FAILED
            analysis_result.error_message = err_msg
            analysis_result.completed_at = django_timezone.now()
            analysis_result.save()
            raise Ignore()

        service = build('gmail', 'v1', credentials=credentials)
        logger.info(f"{log_prefix} Gmail service built.")

        # Fetch Message IDs
        all_message_ids = []
        page_token = None
        MAX_ANALYSIS_PAGES = getattr(settings, 'GMAIL_MAX_ANALYSIS_PAGES', 20)
        MESSAGES_PER_PAGE = 100
        logger.info(f"{log_prefix} Starting message ID fetch (Max Pages: {MAX_ANALYSIS_PAGES})")
        for page_num in range(MAX_ANALYSIS_PAGES):
            try:
                results = service.users().messages().list(userId='me', q='in:inbox', maxResults=MESSAGES_PER_PAGE, pageToken=page_token).execute()
                messages = results.get('messages', [])
                if messages:
                    all_message_ids.extend([m['id'] for m in messages])
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            except HttpError as list_err:
                # --- CORRECTED INDENTATION ---
                logger.error(f"{log_prefix} HTTP error fetching message IDs page {page_num+1}: {list_err}", exc_info=True)
                status = getattr(list_err.resp, 'status', 500)
                if status == 401:
                    logger.error(f"{log_prefix} Auth error (401) during listing. Aborting.")
                    if analysis_result:
                        analysis_result.status = SenderAnalysisResult.StatusChoices.FAILED
                        analysis_result.error_message = "Google Authentication failed during message listing."
                        analysis_result.completed_at = django_timezone.now()
                        analysis_result.save()
                    raise Ignore() from list_err
                else:
                    logger.warning(f"{log_prefix} Attempting retry due to HTTP {status} during listing.")
                    raise self.retry(exc=list_err) from list_err
                # --- END CORRECTION ---
        total_ids_fetched = len(all_message_ids)
        logger.info(f"{log_prefix} Fetched {total_ids_fetched} message IDs.")
        analysis_result.total_ids_fetched = total_ids_fetched
        analysis_result.save(update_fields=['total_ids_fetched', 'updated_at'])

        if total_ids_fetched == 0:
            analysis_result.status = SenderAnalysisResult.StatusChoices.COMPLETED
            analysis_result.completed_at = django_timezone.now()
            analysis_result.sender_counts = {}
            analysis_result.total_messages_processed = 0
            analysis_result.total_errors_encountered = 0
            analysis_result.save()
            logger.info(f"{log_prefix} FINISHED early - No messages.")
            return "Completed: No messages."

        # Process Message Details (Batching)
        senders = {}
        def batch_callback(request_id, response, exception):
            nonlocal senders, total_detail_fetch_errors, processed_detail_count
            processed_detail_count += 1
            if exception:
                total_detail_fetch_errors += 1
                logger.warning(f"{log_prefix} CB Error ReqID={request_id}: {exception}")
            else:
                try:
                    sender_email = parse_sender_from_headers(response.get('payload', {}).get('headers', []))
                    if sender_email:
                        senders[sender_email] = senders.get(sender_email, 0) + 1
                    else: # Count as error if sender couldn't be parsed
                        total_detail_fetch_errors += 1
                except Exception as parse_error:
                    logger.error(f"{log_prefix} CB Error parsing ReqID={request_id}: {parse_error}", exc_info=True)
                    total_detail_fetch_errors += 1

        num_detail_batches = (total_ids_fetched + ANALYSIS_BATCH_LIMIT - 1) // ANALYSIS_BATCH_LIMIT
        logger.info(f"{log_prefix} Processing details in {num_detail_batches} batches.")
        for batch_index, message_id_chunk in enumerate(_chunk_list(all_message_ids, ANALYSIS_BATCH_LIMIT)):
             batch_request = service.new_batch_http_request(callback=batch_callback)
             for msg_id in message_id_chunk:
                 batch_request.add(service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['From']), request_id=f"msg-{msg_id}")
             try:
                 batch_request.execute()
             except HttpError as batch_http_err:
                 status = getattr(batch_http_err.resp, 'status', 500)
                 logger.error(f"{log_prefix} Batch {batch_index+1} HTTP Error Status={status}: {batch_http_err}", exc_info=True)
                 batch_execution_errors += len(message_id_chunk) # Approx error count
                 if status == 401: raise Ignore() from batch_http_err # Fatal auth error
                 raise self.retry(exc=batch_http_err) from batch_http_err # Retry other HTTP errors
             except Exception as batch_exec_err:
                  logger.error(f"{log_prefix} Batch {batch_index+1} FAILED EXECUTION Unexpected: {batch_exec_err}", exc_info=True)
                  batch_execution_errors += len(message_id_chunk) # Approx error count
                  raise self.retry(exc=batch_exec_err) from batch_exec_err # Retry general errors
             if batch_index < num_detail_batches - 1:
                  time.sleep(0.5) # Delay between batches

        # Save Final Results
        logger.info(f"{log_prefix} Batch Loop FINISHED. Processed={processed_detail_count}, Detail Errors={total_detail_fetch_errors}, Batch Exec Errors={batch_execution_errors}")
        final_error_count = total_detail_fetch_errors + batch_execution_errors
        analysis_result.status = SenderAnalysisResult.StatusChoices.COMPLETED
        analysis_result.sender_counts = dict(sorted(senders.items(), key=lambda item: item[1], reverse=True))
        analysis_result.total_messages_processed = processed_detail_count
        analysis_result.total_errors_encountered = final_error_count
        analysis_result.completed_at = django_timezone.now()
        analysis_result.error_message = None
        analysis_result.save()
        logger.info(f"{log_prefix} TASK COMPLETED. Senders={len(senders)}, Processed={processed_detail_count}, Errors={final_error_count}")
        return "Analysis completed successfully."

    except Ignore:
        logger.warning(f"{log_prefix} Task ignored.")
        # Ensure final status is set correctly if aborted mid-processing
        if analysis_result and analysis_result.status == SenderAnalysisResult.StatusChoices.PROCESSING:
             analysis_result.status = SenderAnalysisResult.StatusChoices.FAILED
             analysis_result.error_message = analysis_result.error_message or "Task aborted."
             analysis_result.completed_at = django_timezone.now()
             analysis_result.save()
        return "Task Ignored."
    except MaxRetriesExceededError:
        logger.error(f"{log_prefix} Max retries exceeded.")
        if analysis_result:
             analysis_result.status = SenderAnalysisResult.StatusChoices.FAILED
             analysis_result.error_message = "Task failed after maximum retries."
             analysis_result.completed_at = django_timezone.now()
             analysis_result.save()
        return "Task failed: Max retries."
    except Exception as exc:
        logger.error(f"{log_prefix} TASK FAILED Unexpectedly: {exc}", exc_info=True)
        if analysis_result: # Save error state if possible
             analysis_result.status = SenderAnalysisResult.StatusChoices.FAILED
             analysis_result.error_message = f"Unexpected error: {str(exc)[:500]}"
             analysis_result.completed_at = django_timezone.now()
             analysis_result.save()
        try:
             raise self.retry(exc=exc) from exc # Final retry attempt
        except MaxRetriesExceededError:
             return f"Task failed unexpectedly: {exc} (Max retries exceeded)"


@shared_task(bind=True, default_retry_delay=60 * 10, max_retries=3, name='gmailtool.tasks.process_single_scheduled_rule')
def process_single_scheduled_rule(self, rule_id: int):
    """ Processes a single scheduled deletion rule (identified by rule_id). """
    task_id = self.request.id
    log_prefix = f"[TASK process_single_rule ID:{task_id} RuleID:{rule_id}]"
    logger.info(f"{log_prefix} START processing.")
    rule = None
    try:
        rule = ScheduledDeletionRule.objects.select_related('user').get(id=rule_id)
    except ScheduledDeletionRule.DoesNotExist:
        logger.warning(f"{log_prefix} Rule not found. Ignoring.")
        raise Ignore()

    if not rule.is_active:
        logger.info(f"{log_prefix} Rule inactive for user {rule.user.username}. Skipping.")
        return f"Rule {rule_id} inactive. Skipped."

    rule.last_error = None # Clear previous error before run

    credentials = _get_valid_credentials_for_user(rule.user.id)
    if not credentials:
        err_msg = f"Failed credentials user {rule.user.username}."
        logger.error(f"{log_prefix} {err_msg}")
        rule.last_error = err_msg[:1000]
        rule.last_run_at = django_timezone.now()
        # is_active should have been updated by helper if needed
        rule.save(update_fields=['last_error', 'last_run_at', 'is_active'])
        raise Ignore()

    try:
        service = build('gmail', 'v1', credentials=credentials)
        query = f'from:"{rule.sender_email_to_delete}" in:inbox older_than:1d'
    except Exception as build_error:
        logger.error(f"{log_prefix} Failed build service: {build_error}", exc_info=True)
        rule.last_error = f"Build service error: {build_error}"[:1000]
        rule.last_run_at = django_timezone.now()
        rule.save(update_fields=['last_error', 'last_run_at'])
        raise self.retry(exc=build_error) from build_error

    messages_to_trash_ids = []
    page_token = None
    fetched_count = 0
    list_error_occurred = False
    logger.info(f"{log_prefix} Fetching messages: {query}")
    while True:
        try:
            response = service.users().messages().list(userId='me', q=query, maxResults=SCHEDULED_LIST_PAGE_SIZE, pageToken=page_token).execute()
        except HttpError as e:
            # --- CORRECTED INDENTATION ---
            logger.error(f"{log_prefix} API error listing messages: {e}", exc_info=True)
            list_error_occurred = True
            rule.last_error = f"API list error: {str(e)[:250]}"
            status = getattr(e.resp, 'status', 500)
            if status == 401:
                logger.error(f"{log_prefix} Auth (401) error during listing. Deactivating token/rule.")
                UserOAuthToken.objects.filter(user=rule.user).update(refresh_token=None)
                rule.is_active = False
                # Save immediately before ignoring
                rule.save(update_fields=['last_error', 'is_active'])
                raise Ignore() from e # Stop task
            else:
                # Retry other HTTP errors
                logger.warning(f"{log_prefix} Retrying task due to list error (status {status}).")
                raise self.retry(exc=e) from e
            # --- END CORRECTION ---

        current_batch_ids = [msg['id'] for msg in response.get('messages', [])]
        if current_batch_ids:
            messages_to_trash_ids.extend(current_batch_ids)
            fetched_count += len(current_batch_ids)
        page_token = response.get('nextPageToken')
        if not page_token or not current_batch_ids or fetched_count >= SCHEDULED_MAX_MESSAGES_PER_RUN:
            if fetched_count >= SCHEDULED_MAX_MESSAGES_PER_RUN:
                 logger.warning(f"{log_prefix} Reached MAX_MESSAGES limit ({SCHEDULED_MAX_MESSAGES_PER_RUN}).")
            break

    logger.info(f"{log_prefix} Found {len(messages_to_trash_ids)} messages.")
    actual_trashed_count = 0
    batch_trash_errors = 0
    if messages_to_trash_ids:
        for id_chunk in _chunk_list(messages_to_trash_ids, SCHEDULED_TRASH_BATCH_SIZE):
            batch_results = {'success': 0, 'errors': 0}
            def _trash_cb(req_id, resp, exc):
                nonlocal batch_results
                if exc:
                    batch_results['errors'] += 1
                    logger.warning(f"{log_prefix} Batch trash item error (Req:{req_id}): {exc}")
                else:
                    batch_results['success'] += 1

            batch = service.new_batch_http_request(callback=_trash_cb)
            for msg_id in id_chunk:
                batch.add(service.users().messages().trash(userId='me', id=msg_id))

            try:
                batch.execute()
                actual_trashed_count += batch_results['success']
                batch_trash_errors += batch_results['errors']
                if batch_results['errors'] > 0:
                    logger.warning(f"{log_prefix} Encountered {batch_results['errors']} errors in batch trash.")
                    # Append error note, specific errors logged by callback
                    rule.last_error = (rule.last_error or "") + f" {batch_results['errors']} trash errors in batch. "
                logger.info(f"{log_prefix} Batch trashed {batch_results['success']}. Total run: {actual_trashed_count}")
            except HttpError as e_batch:
                 # --- CORRECTED INDENTATION ---
                 logger.error(f"{log_prefix} API error executing trash batch: {e_batch}", exc_info=True)
                 rule.last_error = (rule.last_error or "") + f" Batch exec error: {str(e_batch)[:100]}. "
                 batch_trash_errors += len(id_chunk) # Assume all failed
                 status = getattr(e_batch.resp, 'status', 500)
                 if status == 401:
                     logger.error(f"{log_prefix} Auth (401) error during batch trash. Deactivating.")
                     UserOAuthToken.objects.filter(user=rule.user).update(refresh_token=None)
                     rule.is_active = False
                     rule.save(update_fields=['last_error', 'is_active'])
                     raise Ignore() from e_batch # Stop task
                 else:
                     # Retry other HTTP errors
                     logger.warning(f"{log_prefix} Retrying task due to batch error (status {status}).")
                     raise self.retry(exc=e_batch) from e_batch
                 # --- END CORRECTION ---
            except Exception as e_unexp_batch:
                 # --- CORRECTED INDENTATION ---
                 logger.error(f"{log_prefix} Unexpected error executing trash batch: {e_unexp_batch}", exc_info=True)
                 rule.last_error = (rule.last_error or "") + " Unexpected batch exec error. "
                 batch_trash_errors += len(id_chunk) # Assume all failed
                 # Retry unexpected errors
                 raise self.retry(exc=e_unexp_batch) from e_unexp_batch
                 # --- END CORRECTION ---

    # Update rule status after processing all batches
    rule.last_run_at = django_timezone.now()
    if rule.last_error:
        rule.last_error = rule.last_error[:1000].strip() # Ensure error fits and trim space
    update_fields = ['last_run_at', 'last_error']
    # is_active is only changed on 401 errors, check instance state if needed
    if hasattr(rule, '_dirtyfields') and 'is_active' in rule._dirtyfields: # More robust check if using django-dirtyfields
        update_fields.append('is_active')
    elif not getattr(rule, 'is_active', True): # Fallback check if field was directly set to False
         if 'is_active' not in update_fields: update_fields.append('is_active')
    rule.save(update_fields=update_fields)

    result_msg = f"Rule {rule_id} processed. Trashed: {actual_trashed_count}."
    if batch_trash_errors > 0: result_msg += f" Encountered {batch_trash_errors} trash errors."
    if list_error_occurred and not rule.last_error: result_msg += " Errors occurred during message listing." # Append general note if specific list error wasn't saved
    logger.info(f"{log_prefix} FINISHED. {result_msg}")
    return result_msg


@shared_task(name='gmailtool.tasks.run_all_active_scheduled_deletions')
def run_all_active_scheduled_deletions():
    """ Master task run by Celery Beat to queue individual rule processing."""
    log_prefix = "[TASK run_all_active_scheduled_deletions]"; logger.info(f"{log_prefix} START.")
    active_rules = ScheduledDeletionRule.objects.filter(is_active=True).select_related('user')
    if not active_rules.exists(): logger.info(f"{log_prefix} No active rules found."); return "No active rules found."
    queued_count = 0; skipped_no_token = 0; processed_users = set()
    for rule in active_rules:
        user = rule.user
        # Check token status only once per user per run
        if user.id not in processed_users:
             has_token = UserOAuthToken.objects.filter(user=user, refresh_token__isnull=False).exists()
             processed_users.add((user.id, has_token)) # Store check result
        else:
             # Retrieve check result
             has_token = next((token_status for uid, token_status in processed_users if uid == user.id), False)

        if has_token:
            try:
                process_single_scheduled_rule.delay(rule.id); queued_count += 1
            except Exception as e_queue:
                logger.error(f"{log_prefix} FAILED queue rule {rule.id} (User: {user.username}): {e_queue}")
        else:
            if rule.is_active: # Only deactivate if it wasn't already found to be tokenless
                 skipped_no_token += 1
                 logger.warning(f"{log_prefix} Skipping rule {rule.id} for {user.username}, no token. Deactivating.")
                 rule.is_active = False
                 rule.last_error = f"Deactivated: No valid Google token."
                 rule.save(update_fields=['is_active', 'last_error'])
    logger.info(f"{log_prefix} FINISHED. Queued {queued_count} tasks. Skipped/Deactivated {skipped_no_token} rules.")
    return f"Queued {queued_count} tasks. Skipped {skipped_no_token}."

# --- REMOVED/Obsolete Tasks ---
# (Keep this section clean or remove commented-out old tasks)