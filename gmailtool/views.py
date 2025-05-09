# gmailtool/views.py

import os
import json
import datetime
import logging
import re # Keep if used by show_senders
import time # Keep if used by show_senders

from django.utils import timezone # Keep standard imports
from django.conf import settings
from django.shortcuts import redirect, render, reverse
from django.contrib import messages
from django.views.decorators.http import require_POST, require_GET # Keep require_POST for delete_now
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest # Renamed
from googleapiclient.discovery import build
# *** ADDED django_auth_login ***
from django.contrib.auth import login as django_auth_login
from django.contrib.auth import get_user_model
from django.contrib.auth import logout as django_auth_logout
from googleapiclient.errors import HttpError
from googleapiclient.http import BatchHttpRequest # Keep if used by show_senders
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseServerError # Added HttpResponseServerError for login errors
from .tasks import background_trash_sender, process_single_scheduled_rule
from .models import UserOAuthToken, ScheduledDeletionRule

# *** ADDED UserOAuthToken import ***
from .models import UserOAuthToken
User = get_user_model()

logger = logging.getLogger(__name__)

# --- Settings Checks and Constants ---
if settings.DEBUG: # Use Django's DEBUG setting to control this
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Define REDIRECT_URI at module level, using the value specified by the user
# This ensures the fallback matches the required value if settings.GOOGLE_OAUTH_REDIRECT_URI is missing
REDIRECT_URI = getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', 'https://inbox-detox.com/oauth2callback/')


# --- Utility Functions (Keep exactly as provided by user) ---
def credentials_to_dict(credentials):
    # Added check for None credentials object
    if not credentials: return {}
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def get_credentials_from_session(request):
    credentials_dict = request.session.get('credentials')
    if not credentials_dict: return None

    # Filter non-None values before passing to Credentials constructor
    valid_creds_data = {k:v for k,v in credentials_dict.items() if v is not None}
    if not valid_creds_data: return None

    try:
        credentials = Credentials(**valid_creds_data)
    except Exception as e:
        logger.error(f"Error creating credentials from session: {e}", exc_info=True)
        return None

    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(GoogleAuthRequest()) # Use renamed import
            request.session['credentials'] = credentials_to_dict(credentials)
            # request.session.save() # Not usually needed here
            logger.info("Session credentials refreshed successfully.")
        except Exception as refresh_error:
            logger.error(f"Error refreshing session credentials token: {refresh_error}", exc_info=True)
            if 'credentials' in request.session: del request.session['credentials']
             # *** START ADDITION: Invalidate DB token on refresh failure ***
            if request.user.is_authenticated:
                 try:
                     token_obj = UserOAuthToken.objects.get(user=request.user)
                     if token_obj.refresh_token: # If there was one
                         token_obj.refresh_token = None # Invalidate it
                         token_obj.save()
                         logger.warning(f"Invalidated DB refresh token for {request.user.username} due to session refresh failure.")
                 except UserOAuthToken.DoesNotExist:
                     pass # No token to invalidate
                 except Exception as e_db:
                     logger.error(f"Error invalidating DB token for {request.user.username}: {e_db}", exc_info=True)
             # *** END ADDITION ***
            return None # Return None as credentials are now bad
    # Check validity *after* potential refresh
    if not credentials.valid:
        logger.warning("Credentials are not valid after potential refresh.")
        return None
    return credentials

@login_required
@require_POST
def schedule_sender_deletion_view(request):
    """Handles POST request to schedule deletion for a sender."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    sender_email_raw = request.POST.get('sender_email')

    if not sender_email_raw:
        msg = "Sender email not provided for scheduling."
        logger.warning(f"{msg} User: {request.user.username}")
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=400)
        messages.error(request, msg); return redirect(reverse('show_senders'))

    sender_email = sender_email_raw.lower().strip() # Normalize

    # Check if user has a persisted refresh token, essential for scheduled tasks
    if not UserOAuthToken.objects.filter(user=request.user, refresh_token__isnull=False).exists():
        msg = "Cannot schedule deletion: Your Google account is not fully linked for background processing. Please re-login with Google and ensure you grant offline access permission."
        logger.warning(f"User {request.user.username} tried to schedule deletion for '{sender_email}' without a refresh token.")
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=403) # Forbidden
        messages.error(request, msg); return redirect(reverse('show_senders'))

    try:
        rule, created = ScheduledDeletionRule.objects.update_or_create(
            user=request.user,
            sender_email_to_delete=sender_email,
            defaults={'is_active': True} # Ensure it's active on create/update
        )

        action_log = "scheduled new" if created else "updated/re-activated"
        logger.info(f"User {request.user.username} {action_log} deletion rule for sender: {sender_email}")
        msg = f"Deletion for emails from {sender_email} (older than 1 day) has been scheduled."
        if not created: msg = f"Scheduled deletion for {sender_email} (older than 1 day) has been re-activated/updated."

        if is_ajax: return JsonResponse({'status': 'success', 'message': msg, 'sender_email': sender_email, 'action': 'scheduled'})
        messages.success(request, msg)
    except Exception as e:
        logger.error(f"Error creating/updating ScheduledDeletionRule for {request.user.username}, sender {sender_email}: {e}", exc_info=True)
        msg = f"An error occurred while trying to schedule deletion for {sender_email}."
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=500)
        messages.error(request, msg)

    return redirect(reverse('show_senders'))

@login_required
@require_POST
def unschedule_sender_deletion_view(request):
    """Handles POST request to unschedule (delete) a deletion rule for a sender."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    sender_email_raw = request.POST.get('sender_email')

    if not sender_email_raw:
        msg = "Sender email not provided for unscheduling."
        logger.warning(f"{msg} User: {request.user.username}")
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=400)
        messages.error(request, msg); return redirect(reverse('show_senders'))

    sender_email = sender_email_raw.lower().strip() # Normalize

    try:
        deleted_count, _ = ScheduledDeletionRule.objects.filter(
            user=request.user,
            sender_email_to_delete=sender_email
        ).delete()

        if deleted_count > 0:
            logger.info(f"User {request.user.username} unscheduled (deleted) deletion rule for sender: {sender_email}")
            msg = f"Scheduled deletion for emails from {sender_email} has been removed."
            if is_ajax: return JsonResponse({'status': 'success', 'message': msg, 'sender_email': sender_email, 'action': 'unscheduled'})
            messages.success(request, msg)
        else:
            logger.info(f"User {request.user.username} tried to unschedule non-existent rule for sender: {sender_email}")
            msg = f"No active schedule found for sender {sender_email} to remove."
            if is_ajax: return JsonResponse({'status': 'info', 'message': msg, 'sender_email': sender_email, 'action': 'not_found'}) # Or 'error' with 404
            messages.info(request, msg)
    except Exception as e:
        logger.error(f"Error deleting ScheduledDeletionRule for {request.user.username}, sender {sender_email}: {e}", exc_info=True)
        msg = f"An error occurred while trying to unschedule deletion for {sender_email}."
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=500)
        messages.error(request, msg)

    return redirect(reverse('show_senders'))

def chunk_list(lst, size):
    """Yield successive size-sized chunks from lst."""
    # BATCH_LIMIT was defined locally in original, keep it that way
    BATCH_LIMIT = 100 # Define locally if not imported
    # The original loop used 'size' from arg, but BATCH_LIMIT was defined.
    # Assuming the intent was to use BATCH_LIMIT:
    for i in range(0, len(lst), BATCH_LIMIT): # Using BATCH_LIMIT
        yield lst[i:i + BATCH_LIMIT] # Using BATCH_LIMIT
    # If 'size' was intended, change loop and yield to use 'size'
# --- End Utility Functions ---


# --- Basic Views (Keep exactly as provided by user) ---
def loading_page(request):
    """Displays intermediate loading page."""
    return render(request, 'gmailtool/loading.html')

def index_page(request):
    """Renders the simple landing/index page."""
    # Added check for authenticated user here as well
    if request.user.is_authenticated and request.session.get('credentials'):
        return redirect(reverse('show_senders'))
    return render(request, 'gmailtool/index.html')
# --- End Basic Views ---

# Make sure this function definition exists in your views.py
@login_required
@require_POST # Or @require_GET depending on how your button/form submits
def run_my_scheduled_deletions_now_view(request):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if not UserOAuthToken.objects.filter(user=request.user, refresh_token__isnull=False).exists():
        msg = "Cannot run: Your Google account isn't fully linked for background tasks. Please re-login with 'offline access'."
        logger.warning(f"User {request.user.username} tried run without refresh token.")
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=403)
        messages.error(request, msg); return redirect(reverse('show_senders'))

    user_active_rules = ScheduledDeletionRule.objects.filter(user=request.user, is_active=True)
    if not user_active_rules.exists():
        msg = "You have no active scheduled deletions to run."
        logger.info(f"User {request.user.username} tried run with no active rules.")
        if is_ajax: return JsonResponse({'status': 'info', 'message': msg})
        messages.info(request, msg); return redirect(reverse('show_senders'))

    queued_count = 0
    tasks_failed_to_queue = 0
    for rule in user_active_rules:
        try:
            # Make sure process_single_scheduled_rule is imported from .tasks
            process_single_scheduled_rule.delay(rule.id)
            queued_count += 1
        except Exception as e:
             tasks_failed_to_queue += 1
             logger.error(f"Failed to queue task for rule {rule.id} (user {request.user.username}): {e}", exc_info=True)

    if queued_count > 0:
        msg = f"{queued_count} of your scheduled deletion processes have been started. Check back later."
        logger.info(f"User {request.user.username} manually triggered {queued_count} rules ({tasks_failed_to_queue} failed to queue).")
        if is_ajax: return JsonResponse({'status': 'success', 'message': msg, 'tasks_queued': queued_count})
        messages.success(request, msg)
    elif tasks_failed_to_queue > 0:
         msg = "Could not start your scheduled deletion processes due to a server issue. Please try again later."
         if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=500)
         messages.error(request, msg)
    # If queued_count is 0 and tasks_failed_to_queue is 0 (shouldn't happen if rules exist), redirect silently or show info.

    return redirect(reverse('show_senders'))
# --- Authentication Views ---
# login view remains exactly the same as user provided
def login(request):
    """Initiates the Google OAuth 2.0 flow."""
    if 'credentials' in request.session: del request.session['credentials']
    if 'oauth_state' in request.session: del request.session['oauth_state']
    try:
        # --- Use settings directly ---
        credentials_json_path = settings.CREDENTIALS_JSON_PATH
        google_oauth_scopes = settings.GOOGLE_OAUTH2_SCOPES
        # Use the REDIRECT_URI defined at the module level, which gets from settings or fallback
        # This ensures consistency with the user's preference.
        redirect_uri_to_use = REDIRECT_URI

        if not all([credentials_json_path, google_oauth_scopes, redirect_uri_to_use]):
             raise AttributeError("Required OAuth settings missing from Django settings or derived constants.")

        flow = Flow.from_client_secrets_file(
            credentials_json_path,
            scopes=google_oauth_scopes,
            redirect_uri=redirect_uri_to_use # Use the derived/checked URI
        )
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
        request.session['oauth_state'] = state
        # request.session.save() # Not required before redirect
        logger.debug(f"Login: Generated state: {state}. Redirecting.")
        return redirect(authorization_url)
    except AttributeError as e_settings:
        logger.error(f"OAuth settings error: {e_settings}", exc_info=True)
        # Render generic error, avoid exposing specific setting names if possible
        return HttpResponseServerError("Server configuration error: OAuth settings incomplete.")
    except FileNotFoundError:
        logger.error(f"Credentials file not found at {settings.CREDENTIALS_JSON_PATH}") # type: ignore
        return HttpResponseServerError("Server configuration error: Credentials file missing.")
    except Exception as e:
        logger.error(f"Error during login initiation: {e}", exc_info=True)
        return HttpResponseServerError(f"An error occurred during the login process: {e}")

# *** MODIFIED oauth2callback ONLY ***
def oauth2callback(request):
    """Handles the callback from Google, fetches token, saves credentials to session,
       links/creates Django user, stores refresh token persistently, and logs user in."""
    returned_state = request.GET.get('state')
    expected_state = request.session.pop('oauth_state', None) # Pop to use once

    logger.debug(f"OAuth2Callback: Returned state={returned_state}, Expected state={expected_state}")

    try:
        # --- Use settings directly ---
        credentials_json_path = settings.CREDENTIALS_JSON_PATH
        google_oauth_scopes = settings.GOOGLE_OAUTH2_SCOPES
        # Use the REDIRECT_URI defined at the module level, which gets from settings or fallback
        redirect_uri_to_use = REDIRECT_URI
        if not all([credentials_json_path, google_oauth_scopes, redirect_uri_to_use]):
             raise AttributeError("Required OAuth settings missing from Django settings or derived constants for callback.")
    except AttributeError as e_settings:
        logger.error(f"OAuth settings error during callback: {e_settings}", exc_info=True)
        messages.error(request, "Server configuration error during authentication.")
        return redirect(reverse('login')) # Use login URL name

    if returned_state is None or expected_state is None or returned_state != expected_state:
        logger.warning(f"State mismatch/missing in callback. URL: {returned_state}, Session: {expected_state}")
        messages.error(request, "Authentication state error. Please try logging in again.")
        return redirect(reverse('login')) # Use login URL name

    try:
        flow = Flow.from_client_secrets_file(
            credentials_json_path, # type: ignore
            scopes=google_oauth_scopes, # type: ignore
            redirect_uri=redirect_uri_to_use, # Use derived/checked URI
            state=expected_state # Pass state for validation
        )

        authorization_response = request.build_absolute_uri()
        # Ensure HTTPS if not in insecure mode
        if not request.is_secure() and os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') != '1':
            if 'http://' in authorization_response:
                authorization_response = authorization_response.replace('http://', 'https://', 1)
                logger.info(f"OAuth2Callback: Rewrote auth response URL to HTTPS: {authorization_response}")

        # --- Fetch Token ---
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials

        # --- Store credentials in session (as before) ---
        request.session['credentials'] = credentials_to_dict(credentials)
        logger.info("Successfully fetched Google token and saved to session.")

        # --- START: Link to Django User & Store Refresh Token ---
        try:
            # 1. Get Google User Info
            user_info_service = build('oauth2', 'v2', credentials=credentials)
            google_user_info = user_info_service.userinfo().get().execute()
            user_email = google_user_info.get('email')

            if not user_email:
                logger.error("Could not retrieve email from Google userinfo.")
                messages.error(request, "Failed to retrieve your email from Google. Cannot complete login.")
                return redirect(reverse('login')) # Use login URL name

            user_email_normalized = user_email.lower()

            # 2. Find or Create Django User
            user, created = User.objects.get_or_create(
                email__iexact=user_email_normalized,
                defaults={
                    'username': user_email_normalized.split('@')[0][:150] if '@' in user_email_normalized else user_email_normalized[:150],
                    'email': user_email_normalized
                }
            )
            if created:
                user.set_unusable_password() # type: ignore
                user.save()
                logger.info(f"Created new Django user: {user.username} for Google email {user_email_normalized}") # type: ignore
            else:
                 if user.email != user_email_normalized: # Ensure email is synced # type: ignore
                    user.email = user_email_normalized # type: ignore
                    user.save(update_fields=['email']) # type: ignore
                 logger.info(f"Found existing Django user: {user.username} for Google email {user_email_normalized}") # type: ignore

            # 3. Persistently store/update the refresh token in the database
            if credentials.refresh_token:
                token_obj, token_created = UserOAuthToken.objects.update_or_create(
                    user=user,
                    defaults={'refresh_token': credentials.refresh_token}
                )
                action_log = "Saved new" if token_created else "Updated existing"
                logger.info(f"{action_log} Google refresh token to DB for user {user.username}.") # type: ignore
            else:
                # Check if one already exists in DB
                has_existing_db_token = UserOAuthToken.objects.filter(user=user, refresh_token__isnull=False).exists()
                if not has_existing_db_token:
                    logger.warning(f"No new refresh token from Google for {user.username}, and none in DB. Offline access may fail.") # type: ignore
                    # Optionally add a user message here if this condition is problematic for expected features
                else:
                    logger.info(f"No new refresh token from Google for {user.username}, using existing DB token for offline.") # type: ignore

            # 4. Log the user into Django session
            django_auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend') # type: ignore
            logger.info(f"User {user.username} logged into Django system via Google.") # type: ignore

            # request.session.save() # Not strictly needed

        except HttpError as e_userinfo:
            logger.error(f"Google API error fetching userinfo: {e_userinfo}", exc_info=True)
            err_content = e_userinfo.content.decode() if hasattr(e_userinfo, 'content') and e_userinfo.content else str(e_userinfo)
            messages.error(request, f"Error fetching your profile from Google: {err_content}. Please try again.")
            return redirect(reverse('login')) # Use login URL name
        except Exception as e_link_user:
            logger.error(f"Error processing user info or Django login: {e_link_user}", exc_info=True)
            messages.error(request, "An error occurred setting up your account. Please try again.")
            return redirect(reverse('login')) # Use login URL name
        # --- END: Link to Django User & Store Refresh Token ---

        # --- Redirect after successful login and potential token storage ---
        return redirect(reverse('loading_page')) # Redirect as before

    except Exception as auth_error: # Catch errors from flow.fetch_token() or other outer steps
        logger.error(f"General OAuth2 callback error: {auth_error}", exc_info=True)
        error_description = getattr(auth_error, 'description', str(auth_error))
        messages.error(request, f"Failed to complete authentication with Google: {error_description}")
        return redirect(reverse('login')) # Use login URL name


# --- Sender Listing View (Keep exactly as provided by user) ---
def show_senders(request):
    # This function remains exactly as in the user's provided code block
    # It uses get_credentials_from_session()
    credentials = get_credentials_from_session(request)
    if not credentials:
        logger.info("No valid credentials in session for show_senders, redirecting to login.")
        messages.info(request, "Please log in to view your senders.")
        return redirect(reverse('login')) # Use login URL name

    context = { 'senders': [], 'error_message': None, 'processing_note': None, }
    try:
        service = build('gmail', 'v1', credentials=credentials)
        messages_list = []
        page_token = None
        messages_per_page = 100
        pages_fetched = 0
        MAX_PAGES = 10
        logger.info(f"show_senders: Fetching message IDs (max {MAX_PAGES * messages_per_page} messages)...")
        while pages_fetched < MAX_PAGES:
             pages_fetched += 1
             logger.debug(f"Fetching page {pages_fetched}/{MAX_PAGES}...")
             try:
                 result = service.users().messages().list(userId='me', q='in:inbox', maxResults=messages_per_page, pageToken=page_token).execute()
             except HttpError as list_error:
                 status_code = list_error.resp.status if hasattr(list_error.resp, 'status') else 'Unknown'
                 logger.error(f"API error during message listing page {pages_fetched}: {list_error} (Status: {status_code})")
                 if list_error.resp.status == 401: # type: ignore
                      messages.error(request, "Authentication error fetching messages. Please log in again.")
                      if 'credentials' in request.session: del request.session['credentials']; request.session.save()
                      return redirect(reverse('login')) # Use login URL name
                 elif list_error.resp.status == 429: # type: ignore
                    logger.warning("Rate limit hit during message listing. Stopping fetch.")
                    messages.warning(request, "Hit API rate limit while fetching messages. Results may be incomplete.")
                    context['error_message'] = "Hit API rate limit fetching messages list. Results incomplete."
                    break
                 else:
                      messages.error(request, f"API Error ({status_code}) fetching message list.")
                      context['error_message'] = f"API Error ({status_code}) fetching messages list."
                      break
             current_messages = result.get('messages', [])
             if current_messages: messages_list.extend(current_messages)
             page_token = result.get('nextPageToken')
             if not page_token: break
             if pages_fetched < MAX_PAGES : time.sleep(0.1)
        if pages_fetched >= MAX_PAGES and page_token:
            logger.warning(f"Reached MAX_PAGES limit ({MAX_PAGES}). Results might be incomplete.")
            context['processing_note'] = f"Showing senders from the first {len(messages_list)} messages (hit display limit)."
        logger.info(f"show_senders: Fetched a total of {len(messages_list)} message IDs.")
        if not messages_list and not context.get('error_message'):
            context['processing_note'] = "No messages found matching the query."
        if messages_list:
            senders = {}
            total_batch_errors = 0
            MESSAGE_DETAIL_BATCH_LIMIT = 100
            MAX_BATCH_TIME_DETAILS = 120
            logger.info(f"show_senders: Preparing to fetch details for {len(messages_list)} messages using batches (limit: {MESSAGE_DETAIL_BATCH_LIMIT}).")
            def batch_callback(request_id, response, exception):
                nonlocal senders, total_batch_errors
                if exception:
                    logger.warning(f"Batch callback error for request_id {request_id}: {exception}")
                    total_batch_errors += 1
                else:
                    try:
                         headers = response.get('payload', {}).get('headers', [])
                         sender_email = None
                         for h in headers:
                             if h['name'].lower() == 'from':
                                 sender_raw = h['value']
                                 match = re.search(r'<([\w\.-]+@[\w\.-]+)>', sender_raw)
                                 if match: sender_email = match.group(1).lower()
                                 else:
                                     match_fallback = re.search(r'[\w\.-]+@[\w\.-]+', sender_raw)
                                     if match_fallback: sender_email = match_fallback.group(0).lower()
                                 break
                         if sender_email: senders[sender_email] = senders.get(sender_email, 0) + 1
                         # else: logger.warning(f"Could not find/parse 'From' header for request {request_id}")
                    except Exception as parse_error:
                          logger.warning(f"Error processing batch response content for request_id {request_id}: {parse_error}")
                          total_batch_errors += 1
            num_detail_batches = (len(messages_list) + MESSAGE_DETAIL_BATCH_LIMIT - 1) // MESSAGE_DETAIL_BATCH_LIMIT
            logger.info(f"Starting batch processing for message details in {num_detail_batches} batches.")
            batches_completed_successfully = 0
            start_time_batches_details = time.time()
            batch_processing_stopped_early_details = False
            for batch_index, message_chunk in enumerate(chunk_list(messages_list, MESSAGE_DETAIL_BATCH_LIMIT)): # type: ignore
                if (time.time() - start_time_batches_details) > MAX_BATCH_TIME_DETAILS:
                     logger.warning(f"Stopping detail batch processing after {MAX_BATCH_TIME_DETAILS}s due to time limit.")
                     messages.warning(request, "Processing stopped due to time limit. Results may be incomplete.")
                     batch_processing_stopped_early_details = True
                     context['error_message'] = (context.get('error_message', '') + " Detail Processing stopped (time limit).").strip()
                     break
                batch = service.new_batch_http_request(callback=batch_callback)
                logger.debug(f"Building detail batch #{batch_index + 1}/{num_detail_batches}...")
                for i, msg in enumerate(message_chunk):
                    request_id = f"msg-{msg['id']}-{batch_index}-{i}" # type: ignore
                    batch.add(service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']), request_id=request_id) # type: ignore
                logger.debug(f"Executing detail batch #{batch_index + 1}...")
                try: batch.execute(); batches_completed_successfully += 1
                except HttpError as batch_exec_error:
                    status_code = batch_exec_error.resp.status if hasattr(batch_exec_error.resp, 'status') else 'Unknown'
                    logger.error(f"Fatal HTTP error executing detail batch #{batch_index + 1}: {batch_exec_error} (Status: {status_code})", exc_info=True)
                    error_detail = f"API Error ({status_code}) during batch processing."
                    context['error_message'] = (context.get('error_message', '') + f" {error_detail}").strip()
                    if status_code == 401:
                         messages.error(request, "Authentication error during processing. Please log in again.")
                         if 'credentials' in request.session: del request.session['credentials']; request.session.save()
                         return redirect(reverse('login')) # Use login URL name
                    batch_processing_stopped_early_details = True; break
                except Exception as batch_exec_error:
                    logger.error(f"Unexpected error executing detail batch #{batch_index + 1}: {batch_exec_error}", exc_info=True)
                    context['error_message'] = (context.get('error_message', '') + " Unexpected batch error.").strip()
                    batch_processing_stopped_early_details = True; break
                if not batch_processing_stopped_early_details and batch_index < num_detail_batches - 1: time.sleep(0.5)
            note_prefix = context.get('processing_note', '')
            if note_prefix and not note_prefix.endswith(" "): note_prefix += " " # type: ignore
            if senders:
                sorted_senders = sorted(senders.items(), key=lambda item: item[1], reverse=True)
                context['senders'] = sorted_senders # type: ignore
                note = f"Displaying sender counts based on {sum(senders.values())} successfully parsed emails"
                if batches_completed_successfully < num_detail_batches or pages_fetched < MAX_PAGES:
                    approx_checked = batches_completed_successfully * MESSAGE_DETAIL_BATCH_LIMIT
                    note += f" (from approx {approx_checked} checked out of {len(messages_list)} found)."
                else: note += f" (from all {len(messages_list)} found)."
                if batch_processing_stopped_early_details: note += " Processing stopped early."
                elif total_batch_errors > 0: note += f" Encountered {total_batch_errors} errors during parsing."
                context['processing_note'] = note_prefix + note # type: ignore
            elif not context.get('error_message'):
                context['processing_note'] = note_prefix + "Could not determine sender counts." # type: ignore
    except HttpError as api_error:
        status_code = api_error.resp.status if hasattr(api_error.resp, 'status') else 'Unknown'
        logger.error(f"Outer API error in show_senders: {api_error} (Status: {status_code})", exc_info=True)
        context['error_message'] = f"API Error ({status_code}) occurred during setup."
        if status_code == 401:
             messages.error(request, "Authentication error. Please log in again.");
             if 'credentials' in request.session: del request.session['credentials']; request.session.save()
             return redirect(reverse('login')) # Use login URL name
    except Exception as general_error:
        logger.error(f"Unexpected error in show_senders: {general_error}", exc_info=True)
        messages.error(request,"An unexpected error occurred while retrieving sender data.")
        context['error_message'] = "An unexpected server error occurred."
    return render(request, 'gmailtool/senders.html', context)

# --- Deletion View (Keep exactly as provided by user) ---
@require_POST
def delete_now(request):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    credentials = get_credentials_from_session(request)
    if not credentials:
        logger.warning("delete_now: Authentication failed (no session credentials).")
        msg = 'Authentication required. Please log in again.'
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=401)
        messages.error(request, msg); return redirect(reverse('login')) # Use login URL name

    sender_email = request.POST.get('sender_email')
    if not sender_email:
        logger.warning("delete_now: Sender email not provided.")
        msg = 'Sender email not provided.'
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=400)
        messages.error(request, msg); return redirect(reverse('show_senders'))

    logger.info(f"Received request to delete NOW for: {sender_email}. Queueing background task.")
    credentials_dict = credentials_to_dict(credentials)
    if not any(credentials_dict.values()):
        logger.error(f"delete_now: Failed to convert credentials to dict for user {request.user.username}.") # type: ignore
        msg = "Internal error processing credentials."
        if is_ajax: return JsonResponse({'status': 'error', 'message': msg}, status=500)
        messages.error(request, msg); return redirect(reverse('show_senders'))

    try:
        # Assuming background_trash_sender expects dict and email
        # Passing user.id if task signature allows it: background_trash_sender.delay(credentials_dict, sender_email, request.user.id)
        task = background_trash_sender.delay(credentials_dict, sender_email)
        logger.info(f"Queued 'delete now' task {task.id} for: {sender_email}") # type: ignore
        success_message = f"Deletion process for ALL messages from {sender_email} started in the background."
        if is_ajax: return JsonResponse({'status': 'success', 'message': success_message, 'task_id': task.id}) # type: ignore
        messages.success(request, success_message); return redirect(reverse('show_senders'))
    except Exception as e:
        logger.error(f"Failed to queue delete_now task for {sender_email}: {e}", exc_info=True)
        error_message = "Failed to start the deletion process. Please try again later."
        if is_ajax: return JsonResponse({'status': 'error', 'message': error_message}, status=500)
        messages.error(request, error_message); return redirect(reverse('show_senders'))
# --- End Deletion View ---


# --- Logout View (Keep exactly as provided by user) ---
def logout(request): # Assuming URL name is 'logout'
    user_identifier = str(request.user.username if request.user.is_authenticated else "AnonymousUser-logout")
    logger.info(f"Logout process initiated for user: {user_identifier}")

    django_auth_logout(request)
    logger.info(f"Django logout completed for user: {user_identifier}")

    session_keys_to_clear = ['credentials', 'oauth_state']
    cleared_keys = []
    for key in session_keys_to_clear:
        if request.session.pop(key, None) is not None: cleared_keys.append(key)

    if cleared_keys: logger.info(f"Cleared custom session keys for {user_identifier}: {cleared_keys}")
    # No need to save session, django_auth_logout does it.

    messages.success(request, "You have been successfully logged out.")
    return redirect(reverse('login')) # Use login URL name
# --- END Logout View ---