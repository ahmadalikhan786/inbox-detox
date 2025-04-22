# gmailtool/views.py

import os
import json
import datetime
import logging
from django.utils import timezone
from django.conf import settings
from django.shortcuts import redirect, render, reverse
from django.contrib import messages
from django.views.decorators.http import require_POST
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from django.http import HttpResponseServerError, HttpResponseRedirect

from .scheduler import get_scheduler, scheduler

logger = logging.getLogger(__name__)

# --- Settings Checks and Constants ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Dev only!
REDIRECT_URI = 'http://localhost:8000/oauth2callback/'
# Ensure settings vars are checked/defined as before

# --- Helper Functions ---
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def get_credentials_from_session(request):
    credentials_dict = request.session.get('credentials')
    if not credentials_dict: return None
    credentials = Credentials(**credentials_dict)
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            request.session['credentials'] = credentials_to_dict(credentials)
            request.session.save() # Save updated credentials
            logger.info("Credentials refreshed successfully.")
        except Exception as refresh_error:
            logger.error(f"Error refreshing credentials token: {refresh_error}")
            if 'credentials' in request.session: del request.session['credentials']
            return None
    return credentials

# --- Core Deletion Logic (Keep as before) ---
def trash_messages_from_sender(credentials_dict, sender_email):
    # ... (Keep the detailed trash_messages_from_sender function as provided previously)
    if not credentials_dict or not sender_email: # Basic check
        logger.error("trash_messages_from_sender called with missing credentials or sender email.")
        return 0, "Missing required data."
    logger.info(f"Starting trash process for sender: {sender_email}")
    count = 0
    error_message = None
    try:
        credentials = Credentials(**credentials_dict)
        # ... (rest of the logic: refresh check, build service, list, batchModify)
        if credentials.expired and credentials.refresh_token:
             try:
                 credentials.refresh(Request())
                 logger.info(f"Refreshed credentials during trash process for {sender_email}")
             except Exception as refresh_error:
                 logger.error(f"Failed to refresh credentials during trash process for {sender_email}: {refresh_error}")
                 return 0, f"Authentication expired for {sender_email}."

        service = build('gmail', 'v1', credentials=credentials)
        query = f'from:"{sender_email}" in:inbox'
        logger.debug(f"Gmail API query: {query}")
        messages_to_trash = []
        page_token = None
        while True: # Paginate through results
             response = service.users().messages().list(userId='me', q=query, maxResults=500, pageToken=page_token).execute()
             messages = response.get('messages', [])
             messages_to_trash.extend([msg['id'] for msg in messages])
             logger.info(f"Found {len(messages)} messages from {sender_email} page. Total: {len(messages_to_trash)}")
             page_token = response.get('nextPageToken')
             if not page_token: break

        if not messages_to_trash:
             logger.info(f"No messages found in inbox from {sender_email}.")
             return 0, f"No messages found in inbox from {sender_email}."

        batch_size = 1000
        total_trashed = 0
        for i in range(0, len(messages_to_trash), batch_size): # Process in batches
             batch_ids = messages_to_trash[i:i + batch_size]
             if not batch_ids: continue
             try:
                 logger.info(f"Trashing batch of {len(batch_ids)} messages from {sender_email}...")
                 body = {'ids': batch_ids, 'addLabelIds': ['TRASH'], 'removeLabelIds': ['INBOX']}
                 service.users().messages().batchModify(userId='me', body=body).execute()
                 total_trashed += len(batch_ids)
                 logger.info(f"Successfully trashed batch. Total trashed: {total_trashed}")
             except HttpError as batch_error:
                 logger.error(f"API error during batch trash for {sender_email}: {batch_error}")
                 error_message = f"API error trashing messages from {sender_email} ({batch_error.resp.status}). Some might remain."
                 break # Stop on error
             except Exception as e:
                 logger.error(f"Unexpected error during batch trash for {sender_email}: {e}")
                 error_message = f"Unexpected error trashing messages from {sender_email}."
                 break # Stop on error
        count = total_trashed
        if not error_message: logger.info(f"Successfully trashed {count} messages from {sender_email}.")

    except HttpError as error:
        logger.error(f"API error setting up trash process for {sender_email}: {error}")
        error_message = f"API Error ({error.resp.status}) processing {sender_email}."
    except Exception as e:
        logger.error(f"Unexpected error during trash process for {sender_email}: {e}", exc_info=True)
        error_message = f"Unexpected error processing {sender_email}."
    return count, error_message


# --- Authentication Views ---
def login(request):
    """Initiates the Google OAuth 2.0 flow."""
    if 'credentials' in request.session: del request.session['credentials']
    if 'oauth_state' in request.session: del request.session['oauth_state']
    try:
        # ... (settings checks)
        if not hasattr(settings, 'CREDENTIALS_JSON_PATH') or not hasattr(settings, 'GOOGLE_OAUTH2_SCOPES'):
             logger.error("CREDENTIALS_JSON_PATH or GOOGLE_OAUTH2_SCOPES not defined in settings.py")
             return HttpResponseServerError("Server configuration error: OAuth settings missing.")

        flow = Flow.from_client_secrets_file(settings.CREDENTIALS_JSON_PATH, scopes=settings.GOOGLE_OAUTH2_SCOPES, redirect_uri=REDIRECT_URI)
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
        request.session['oauth_state'] = state
        request.session.save()  # <<< Force save session before redirect
        logger.debug(f"Login: Generated state: {state}. Session saved.")
        return redirect(authorization_url)
    except FileNotFoundError:
        logger.error(f"Credentials file not found at {settings.CREDENTIALS_JSON_PATH}")
        return HttpResponseServerError("Server configuration error: Credentials file missing.")
    except Exception as e:
        logger.error(f"Error during login initiation: {e}")
        return HttpResponseServerError(f"An error occurred during the login process: {e}")


def oauth2callback(request):
    """Handles the callback from Google, fetches token, saves credentials, redirects."""
    returned_state = request.GET.get('state')
    expected_state = request.session.get('oauth_state')
    logger.debug(f"Callback: Returned state={returned_state}, Expected state={expected_state}")

    # --- State Validation ---
    if returned_state is None or expected_state is None or returned_state != expected_state:
        logger.warning(f"State mismatch/missing in callback. URL: {returned_state}, Session: {expected_state}")
        if 'oauth_state' in request.session: del request.session['oauth_state']
        messages.error(request, "Authentication state error. Please try logging in again.")
        return redirect(reverse('login')) # Redirect to login on state error

    # State is valid, remove it from session
    del request.session['oauth_state']

    # --- Fetch Token ---
    try:
        flow = Flow.from_client_secrets_file(settings.CREDENTIALS_JSON_PATH, scopes=settings.GOOGLE_OAUTH2_SCOPES, redirect_uri=REDIRECT_URI)
        authorization_response = request.build_absolute_uri()
        # ... (potential http->https replacement if needed)
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        request.session['credentials'] = credentials_to_dict(credentials)
        request.session.save() # Save session explicitly
        logger.info("Successfully fetched token and saved credentials.")

        # --- Redirect to the sender list view ---
        return redirect(reverse('show_senders')) # Use the name from urls.py

    except Exception as auth_error:
        logger.error(f"Error during token fetch or credential storage: {auth_error}", exc_info=True)
        messages.error(request, f"Failed to complete authentication with Google: {auth_error}")
        return redirect(reverse('login')) # Redirect to login on auth error


# --- View to Display Senders (Reintroduced) ---
def show_senders(request):
    """Fetches and displays the list of senders from user's Gmail inbox."""
    credentials = get_credentials_from_session(request)
    if not credentials:
        logger.info("No valid credentials in session for show_senders, redirecting to login.")
        messages.info(request, "Please log in to view your senders.")
        return redirect(reverse('login'))

    context = {'senders': [], 'error_message': None} # Default context

    try:
        service = build('gmail', 'v1', credentials=credentials)
        # --- Get list of messages (with pagination) ---
        messages_list = [] # Renamed from messages to avoid confusion
        page_token = None
        max_pages_to_fetch = 5
        messages_per_page = 100
        pages_fetched = 0
        logger.info("show_senders: Fetching message list...")
        # ... (Keep the message listing loop as before)
        while pages_fetched < max_pages_to_fetch:
             pages_fetched += 1
             result = service.users().messages().list(userId='me', q='in:inbox', maxResults=messages_per_page, pageToken=page_token).execute()
             messages_list.extend(result.get('messages', []))
             page_token = result.get('nextPageToken')
             if not page_token: break
        logger.info(f"show_senders: Fetched {len(messages_list)} message IDs.")

        # --- Count emails per sender (with limit) ---
        senders = {}
        processed_count = 0
        message_details_fetch_limit = 200
        logger.info(f"show_senders: Fetching message details (limit {message_details_fetch_limit})...")
        # ... (Keep the message details fetching loop as before)
        for msg in messages_list:
            if processed_count >= message_details_fetch_limit: break
            try:
                # ... (get message detail, parse 'From', count)
                msg_detail = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From']).execute()
                processed_count += 1
                headers = msg_detail.get('payload', {}).get('headers', [])
                sender_email = None
                for h in headers:
                     if h['name'].lower() == 'from':
                          sender_raw = h['value']
                          if '<' in sender_raw and '>' in sender_raw:
                              start, end = sender_raw.rfind('<'), sender_raw.rfind('>')
                              if start < end: sender_email = sender_raw[start+1:end].strip().lower()
                          else: sender_email = sender_raw.strip().lower()
                          break
                if sender_email: senders[sender_email] = senders.get(sender_email, 0) + 1
            except HttpError as msg_error: logger.warning(f"show_senders: Error fetching msg ID {msg.get('id', 'N/A')}: {msg_error}. Skipping.")
            except Exception as detail_error: logger.warning(f"show_senders: Error processing msg details {msg.get('id', 'N/A')}: {detail_error}. Skipping.")

        logger.info("show_senders: Finished processing message details.")
        sorted_senders = sorted(senders.items(), key=lambda item: item[1], reverse=True)
        context['senders'] = sorted_senders # Update context

    except HttpError as api_error:
        logger.error(f"API error fetching senders in show_senders: {api_error}")
        messages.error(request, f"API Error ({api_error.resp.status}) fetching sender data. Please try logging in again.")
        # Optionally clear credentials if they might be invalid
        if 'credentials' in request.session: del request.session['credentials']
        return redirect(reverse('login'))
    except Exception as fetch_error:
        logger.error(f"Unexpected error fetching senders in show_senders: {fetch_error}", exc_info=True)
        messages.error(request,"An unexpected error occurred while retrieving sender data.")
        # Stay on the page but show error via context ? Or redirect to login?
        # Let's redirect to login for simplicity on unexpected errors here
        return redirect(reverse('login'))

    # Render the template with the fetched data (or empty list if none found)
    return render(request, 'gmailtool/senders.html', context)


# --- Deletion Views (Updated Redirect) ---
@require_POST
def delete_now(request):
    credentials = get_credentials_from_session(request)
    if not credentials:
        messages.error(request, "Authentication required. Please log in again.")
        return redirect(reverse('login'))

    sender_email = request.POST.get('sender_email')
    if not sender_email:
        messages.error(request, "Sender email not provided.")
        return redirect(reverse('show_senders')) # Redirect to sender list

    logger.info(f"Received request to delete now for: {sender_email}")
    count, error_msg = trash_messages_from_sender(credentials_to_dict(credentials), sender_email)

    if error_msg:
        messages.error(request, f"Error deleting emails from {sender_email}: {error_msg}")
    else:
        messages.success(request, f"Successfully moved {count} email(s) from {sender_email} to Trash.")

    # Redirect back to the sender list view
    return redirect(reverse('show_senders'))


@require_POST
def delete_later(request):
    credentials = get_credentials_from_session(request)
    if not credentials:
        messages.error(request, "Authentication required. Please log in again.")
        return redirect(reverse('login'))

    sender_email = request.POST.get('sender_email')
    if not sender_email:
        messages.error(request, "Sender email not provided.")
        return redirect(reverse('show_senders')) # Redirect to sender list

    logger.info(f"Received request to delete later for: {sender_email}")
    try:
        scheduler_instance = get_scheduler()
        if not scheduler_instance: raise Exception("Scheduler is not running or available.")
        run_time = timezone.now() + datetime.timedelta(hours=1)
        credentials_dict = credentials_to_dict(credentials)
        job_id = f"delete_{sender_email}_{timezone.now().timestamp()}"
        job = scheduler_instance.add_job(
            trash_messages_from_sender, trigger='date', run_date=run_time,
            args=[credentials_dict, sender_email], id=job_id,
            replace_existing=True, misfire_grace_time=300
        )
        logger.info(f"Scheduled job {job.id} for {sender_email} at {run_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        messages.success(request, f"Scheduled deletion for emails from {sender_email} in one hour.")
    except Exception as e:
        logger.error(f"Error scheduling deletion for {sender_email}: {e}", exc_info=True)
        messages.error(request, f"Failed to schedule deletion for {sender_email}: {e}")

    # Redirect back to the sender list view
    return redirect(reverse('show_senders'))


# --- Optional Logout View ---
def logout(request):
    # ... (keep logout view as before)
    session_keys_to_clear = ['credentials', 'oauth_state']
    for key in session_keys_to_clear:
        if key in request.session: del request.session[key]
    logger.info("User logged out, session cleared.")
    messages.info(request, "You have been logged out.")
    return redirect(reverse('login'))