# gmailtool/utils.py

import logging
import time # <--- Ensure this is present
import re   # <--- Ensure this is present for parse_sender_from_headers
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request # <--- Ensure this is imported for refresh

logger = logging.getLogger(__name__)

# --- Constants for Utilities ---
UTIL_BATCH_MODIFY_LIMIT = 1000 # Gmail API limit for batchModify/batchTrash
UTIL_LIST_PAGE_SIZE = 500    # How many message IDs to fetch per list() call
UTIL_RETRY_DELAY_SECONDS = 5 # Base delay for retries
UTIL_MAX_RETRIES = 3         # Max retries for API calls within utils

# --- Utility function for batching ---
def chunk_list(lst, size):
    """Yield successive size-sized chunks from lst."""
    if not isinstance(size, int) or size < 1:
        raise ValueError("Chunk size must be a positive integer")
    for i in range(0, len(lst), size):
        yield lst[i:i + size]

# --- Credential Helpers (PLACEHOLDERS - Keep as is for now) ---
def get_credentials_for_user(user_id):
    """
    PLACEHOLDER: Securely retrieve stored credentials (ideally refresh token)
    for the user and build a Credentials object.
    *** IMPLEMENT THIS SECURELY LATER ***
    """
    logger.warning(f"Using PLACEHOLDER get_credentials_for_user for user {user_id}. IMPLEMENT SECURE STORAGE AND RETRIEVAL.")
    return None

def refresh_credentials_if_needed(credentials, user_id):
    """
    PLACEHOLDER: Check if credentials object needs refreshing and attempts to
    refresh using the refresh_token. Refreshes IN PLACE. Returns updated creds or None on failure.
    *** IMPLEMENT THIS SECURELY LATER ***
    """
    logger.debug(f"(Placeholder) Checking credentials for user {user_id}. Valid: {credentials.valid if credentials else 'N/A'}, Expired: {credentials.expired if credentials else 'N/A'}, Refresh Token: {'Yes' if credentials and credentials.refresh_token else 'No'}")
    if not credentials:
        logger.warning(f"(Placeholder) No credentials provided to refresh_credentials_if_needed for user {user_id}.")
        return None
    try:
        refreshed = False
        if credentials.expired and credentials.refresh_token:
            logger.info(f"(Placeholder) Attempting to refresh credentials for user {user_id}")
            credentials.refresh(Request()) # Use the imported Request
            # save_refreshed_credentials(user_id, credentials) # You would save the updated token here in a real implementation
            logger.info(f"(Placeholder) Refresh attempt complete for user {user_id}. Credentials NOW Valid: {credentials.valid}")
            refreshed = True
            if not credentials.valid:
                 logger.error(f"(Placeholder) Credentials remained invalid after refresh attempt for user {user_id}.")
                 return None # Refresh failed to make them valid

        elif not credentials.valid and not credentials.refresh_token:
             logger.warning(f"(Placeholder) Credentials invalid for user {user_id} and cannot refresh (no refresh token).")
             return None # Invalid and cannot be fixed

        # If we get here, credentials are valid (either initially or after refresh)
        # Or they were expired but had no refresh token (still return them, calling code should check validity)
        # Or they were invalid but had a refresh token, and refresh failed (returned None above)
        if refreshed:
             logger.debug(f"(Placeholder) Returning REFRESHED credentials object for user {user_id}.")
        else:
             logger.debug(f"(Placeholder) Returning original (or unrefreshable) credentials object for user {user_id}. Caller should check validity.")
        return credentials

    except Exception as e:
        logger.error(f"(Placeholder) Error during credential refresh attempt for user {user_id}: {e}", exc_info=True)
        return None # Return None on exception during refresh
# ------------------------------------------------------------------------

# --- Sender Parsing Helper (Keep as is) ---
def parse_sender_from_headers(headers):
    if not headers: return None
    for h in headers:
        if h['name'].lower() == 'from':
            sender_raw = h['value']
            # Robust parsing example:
            sender_email = None
            if '<' in sender_raw and '>' in sender_raw:
                start = sender_raw.rfind('<')
                end = sender_raw.rfind('>')
                if start != -1 and end != -1 and start < end:
                    sender_email = sender_raw[start+1:end].strip().lower()
            # Fallback or alternative parsing if needed
            if not sender_email:
                match = re.search(r'[\w\.-]+@[\w\.-]+', sender_raw)
                if match: sender_email = match.group(0).lower()
                # else: sender_email = sender_raw.strip().lower() # Fallback to raw value if desperate?
            return sender_email # Return the parsed email or None
    return None # Return None if 'From' header not found

# --- Existing trash_messages_from_sender (Keep EXACTLY as provided) ---
def trash_messages_from_sender(credentials_dict, sender_email):
    """
    Finds ALL messages from a specific sender (matching query) and moves
    them to trash using batchModify. Includes detailed logging.
    Returns tuple: (count_successfully_trashed, error_message_or_None)
    """
    if not credentials_dict or not sender_email:
        logger.error("@@@ TRASH UTIL: Called with missing credentials or sender email.")
        return 0, "Missing required data."

    logger.info(f"@@@ TRASH UTIL: Starting trash process for sender: {sender_email}")
    count = 0 # RENAME this variable inside the function to avoid conflict if calling other utils
    total_trashed_in_this_func = 0 # Use a different name for the counter
    error_message = None
    credentials = None
    service = None

    try:
        # --- 1. Credentials and Service ---
        logger.debug(f"@@@ TRASH UTIL: Attempting to build credentials from dict keys: {list(credentials_dict.keys()) if isinstance(credentials_dict, dict) else 'Invalid Type'}")
        credentials = Credentials(**credentials_dict)
        logger.info(f"@@@ TRASH UTIL: Initial creds built - Valid: {credentials.valid}, Expired: {credentials.expired}, Refresh Token: {'Yes' if credentials.refresh_token else 'No'}")

        # --- Attempt Refresh if needed ---
        if credentials.expired and credentials.refresh_token:
             logger.info(f"@@@ TRASH UTIL: Credentials expired, attempting refresh...")
             try:
                 credentials.refresh(Request()) # Use the imported Request
                 logger.info(f"@@@ TRASH UTIL: Refresh Attempt COMPLETE. Credentials NOW Valid: {credentials.valid}")
                 if not credentials.valid:
                      raise ValueError("Credentials remained invalid after refresh attempt.")
                 # NOTE: In a real app, you'd save the refreshed credentials here
                 # save_refreshed_credentials(user_id, credentials) # Pass user_id if available
             except Exception as refresh_error:
                 logger.error(f"@@@ TRASH UTIL: Refresh FAILED: {refresh_error}", exc_info=True)
                 return 0, f"Authentication expired and refresh failed: {refresh_error}"
        elif not credentials.valid:
             logger.error(f"@@@ TRASH UTIL: Initial credentials invalid and cannot be refreshed.")
             return 0, "Invalid credentials provided, cannot refresh."

        # --- Build Service with potentially refreshed credentials ---
        service = build('gmail', 'v1', credentials=credentials)
        logger.info(f"@@@ TRASH UTIL: Gmail service built successfully.")

        # --- 2. Fetch ALL Message IDs using Pagination ---
        # Ensure sender_email is quoted if it contains spaces or special chars, though less common for emails
        query = f'from:"{sender_email}"' # Kept original query logic
        # Add 'in:inbox' back if that was the original intent: query = f'from:"{sender_email}" in:inbox'
        logger.info(f"@@@ TRASH UTIL: Starting ID fetch with query: '{query}'")
        messages_to_trash = []
        page_token = None
        fetch_attempts = 0
        list_pages_fetched = 0
        max_list_retries = UTIL_MAX_RETRIES # Use constant

        while True:
            try:
                logger.debug(f"@@@ TRASH UTIL: Fetching list page {list_pages_fetched + 1} with token: {'Yes' if page_token else 'No'}")
                response = service.users().messages().list(
                    userId='me',
                    q=query,
                    maxResults=UTIL_LIST_PAGE_SIZE, # Use constant
                    pageToken=page_token
                ).execute()
                list_pages_fetched += 1
                messages = response.get('messages', [])
                if messages:
                    messages_to_trash.extend([msg['id'] for msg in messages])
                    logger.debug(f"@@@ TRASH UTIL: Fetched page {list_pages_fetched}, added {len(messages)} IDs. Total listed: {len(messages_to_trash)}")

                page_token = response.get('nextPageToken')
                fetch_attempts = 0 # Reset retry counter on success

                if not page_token:
                    logger.info(f"@@@ TRASH UTIL: Finished fetching IDs. Total IDs found: {len(messages_to_trash)}")
                    break # Exit the loop gracefully

                time.sleep(0.2) # Small delay between list calls

            except HttpError as list_error:
                 status_code = list_error.resp.status if hasattr(list_error.resp, 'status') else 'Unknown'
                 logger.warning(f"@@@ TRASH UTIL: API error fetching message page {list_pages_fetched}: {list_error} (Status: {status_code})")
                 if status_code in [429, 500, 503] and fetch_attempts < max_list_retries: # Retry on rate limit/server error
                     fetch_attempts += 1
                     wait_time = UTIL_RETRY_DELAY_SECONDS * (2**fetch_attempts)
                     logger.warning(f"@@@ TRASH UTIL: Retrying list page fetch in {wait_time}s (attempt {fetch_attempts+1}/{max_list_retries+1})...")
                     time.sleep(wait_time)
                     # Optional: Refresh credentials again after a long sleep
                     try:
                         if credentials.expired and credentials.refresh_token: credentials.refresh(Request())
                     except Exception: logger.warning("@@@ TRASH UTIL: Ignoring credential refresh error during list retry.")
                     continue # Retry fetching this page
                 elif status_code == 403:
                      logger.error(f"@@@ TRASH UTIL: Permission denied (403) fetching list. Check scopes/permissions.")
                      return 0, f"Permission denied (403) fetching messages. Scope issue?"
                 else:
                    error_message = f"API Error (Status: {status_code}) fetching messages list. Aborting trash."
                    logger.error(error_message)
                    return 0, error_message
            except Exception as list_exc:
                 logger.error(f"@@@ TRASH UTIL: Unexpected error fetching message page {list_pages_fetched}: {list_exc}", exc_info=True)
                 error_message = f"Unexpected error fetching messages list. Aborting trash."
                 return 0, error_message


        # --- 3. Batch Modify Messages ---
        if not messages_to_trash:
             logger.info(f"@@@ TRASH UTIL: No messages found matching query for {sender_email}. Nothing to trash.")
             return 0, None

        batch_size = UTIL_BATCH_MODIFY_LIMIT # Use constant
        # Use the renamed counter: total_trashed_in_this_func
        batch_errors = 0
        max_batch_retries = UTIL_MAX_RETRIES # Use constant
        logger.info(f"@@@ TRASH UTIL: Starting batchModify for {len(messages_to_trash)} messages...")

        for batch_index, batch_ids in enumerate(chunk_list(messages_to_trash, batch_size)):
             if not batch_ids: continue

             batch_attempts = 0
             current_batch_failed = False
             while batch_attempts <= max_batch_retries: # Loop for retries
                 try:
                     first_id_in_batch = batch_ids[0]
                     logger.info(f"@@@ TRASH UTIL: Attempting batchModify for {len(batch_ids)} IDs (Batch {batch_index + 1}, Attempt {batch_attempts + 1}/{max_batch_retries+1}). First ID: {first_id_in_batch}")
                     # Using batchModify to add TRASH label and remove INBOX
                     body = {'ids': batch_ids, 'addLabelIds': ['TRASH'], 'removeLabelIds': ['INBOX']}
                     service.users().messages().batchModify(userId='me', body=body).execute()
                     logger.info(f"@@@ TRASH UTIL: batchModify SUCCESS for Batch {batch_index + 1} (First ID: {first_id_in_batch}).")
                     total_trashed_in_this_func += len(batch_ids) # Increment the renamed counter
                     current_batch_failed = False
                     break # Success for this batch

                 except HttpError as batch_error:
                     status_code = batch_error.resp.status if hasattr(batch_error.resp, 'status') else 'Unknown'
                     logger.error(f"@@@ TRASH UTIL: batchModify FAILED for Batch {batch_index + 1} (Attempt {batch_attempts + 1}). Status: {status_code}, Error: {batch_error}")
                     current_batch_failed = True
                     if status_code == 403:
                         logger.error(f"@@@ TRASH UTIL: Permission denied (403) during batchModify. Check scopes (gmail.modify needed). Aborting further batches.")
                         error_message = f"Permission denied (403) trashing messages. Check scopes."
                         return total_trashed_in_this_func, error_message # Stop processing
                     # Retry only on 429, 500, 503
                     elif status_code in [429, 500, 503] and batch_attempts < max_batch_retries:
                        batch_attempts += 1
                        wait_time = UTIL_RETRY_DELAY_SECONDS * (2**batch_attempts)
                        logger.warning(f"@@@ TRASH UTIL: Retrying batchModify in {wait_time}s (Attempt {batch_attempts + 1}/{max_batch_retries+1})...")
                        time.sleep(wait_time)
                        # Optional: Refresh creds again during batch retry?
                        try:
                            if credentials.expired and credentials.refresh_token: credentials.refresh(Request())
                        except Exception: logger.warning("@@@ TRASH UTIL: Ignoring credential refresh error during batch retry.")
                        continue # Retry this batch
                     else: # Non-retryable HTTP error or max retries exceeded for batch
                         logger.error(f"@@@ TRASH UTIL: Non-retryable error or max retries exceeded for Batch {batch_index + 1}.")
                         break # Exit retry loop for this batch, proceed to next batch

                 except Exception as e:
                     logger.error(f"@@@ TRASH UTIL: batchModify UNEXPECTED failure for Batch {batch_index + 1} (Attempt {batch_attempts + 1}). Error: {e}", exc_info=True)
                     current_batch_failed = True
                     break # Exit retry loop for this batch, proceed to next batch

             # After retry loop for one batch:
             if current_batch_failed:
                 batch_errors += 1
                 # Update error message but continue processing other batches
                 error_message = f"Completed, but encountered errors on {batch_errors} batches (check logs)."

             # Delay between batches
             if batch_index < (len(messages_to_trash) // batch_size) -1 : # Check if not the last batch
                time.sleep(1.0) # Use a consistent delay

        # --- Finished processing all batches ---
        if batch_errors == 0:
             logger.info(f"@@@ TRASH UTIL: Successfully completed trashing {total_trashed_in_this_func} messages for {sender_email}.")
             error_message = None # Explicitly set to None on full success
        else:
             logger.warning(f"@@@ TRASH UTIL: Completed trashing {total_trashed_in_this_func} messages for {sender_email} with {batch_errors} batch failures.")
             # error_message will contain the message set above

    # --- 4. Final Error Handling ---
    except HttpError as error:
        status_code = error.resp.status if hasattr(error.resp, 'status') else 'Unknown'
        logger.error(f"@@@ TRASH UTIL: API error during setup phase for {sender_email}: {error} (Status: {status_code})", exc_info=True)
        error_message = f"API Error (Status: {status_code}) setting up process for {sender_email}."
    except Exception as e:
        logger.error(f"@@@ TRASH UTIL: Unexpected error during trash process setup/logic for {sender_email}: {e}", exc_info=True)
        error_message = f"Unexpected error processing {sender_email}: {e}"

    # Use the renamed counter for the return value
    logger.info(f"@@@ TRASH UTIL: Returning final result - Count: {total_trashed_in_this_func}, Error: '{error_message}'")
    return total_trashed_in_this_func, error_message


# ===============================================================
# --- NEW UTILITY FUNCTION FOR 'SCHEDULE DELETION' (Older Than) ---
# ===============================================================
def trash_messages_matching_query(credentials_dict, query, log_identifier="Query Based Deletion"):
    """
    Finds and trashes messages matching a specific Gmail query string
    using pagination and batchModify requests. Includes detailed logging.

    Args:
        credentials_dict (dict): Dictionary representation of Google OAuth credentials.
        query (str): The Gmail search query string (e.g., "from:a@b.com older_than:7d").
        log_identifier (str): A string to identify the source of the call in logs.

    Returns:
        tuple: (total_trashed_count, error_message)
               error_message is None on success, or a string describing the failure.
    """
    if not credentials_dict or not query:
        logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Called with missing credentials or query.")
        return 0, "Missing required data (credentials or query)."

    logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Starting for Query='{query}'")
    total_trashed_count = 0
    error_message = None
    service = None
    credentials = None

    try:
        # 1. Get and Refresh Credentials
        logger.debug(f"@@@ TRASH QUERY UTIL ({log_identifier}): Building credentials.")
        try:
            credentials = Credentials(**credentials_dict)
            logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Initial creds - Valid: {credentials.valid}, Expired: {credentials.expired}, Refresh: {'Yes' if credentials.refresh_token else 'No'}")

            if credentials.expired and credentials.refresh_token:
                logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Credentials expired, attempting refresh...")
                credentials.refresh(Request())
                logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Refresh attempt COMPLETE. Valid: {credentials.valid}")
                if not credentials.valid:
                    raise ValueError("Credentials remained invalid after refresh.")
                # NOTE: Consider saving refreshed credentials if needed by your application
            elif not credentials.valid:
                 logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Initial credentials invalid and cannot refresh.")
                 return 0, "Invalid credentials provided, cannot refresh."

        except Exception as cred_error:
            logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Credential error: {cred_error}", exc_info=True)
            return 0, f"Credential error: {cred_error}"

        # 2. Build Gmail Service
        try:
            service = build('gmail', 'v1', credentials=credentials)
            logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Gmail service built successfully.")
        except Exception as build_error:
            logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Error building Gmail service: {build_error}", exc_info=True)
            return 0, f"Error building Gmail service: {build_error}"

        # 3. List Message IDs Matching Query (Pagination)
        message_ids = []
        page_token = None
        retries = 0
        max_list_retries = UTIL_MAX_RETRIES # Use constant
        list_pages_fetched = 0

        logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Fetching message IDs with query: {query}")
        while True:
            try:
                logger.debug(f"@@@ TRASH QUERY UTIL ({log_identifier}): Fetching list page {list_pages_fetched + 1}, Token: {'Yes' if page_token else 'No'}")
                response = service.users().messages().list(
                    userId='me',
                    q=query,
                    maxResults=UTIL_LIST_PAGE_SIZE, # Use constant
                    pageToken=page_token
                ).execute()
                list_pages_fetched += 1

                messages = response.get('messages', [])
                if messages:
                    message_ids.extend([msg['id'] for msg in messages])
                    logger.debug(f"@@@ TRASH QUERY UTIL ({log_identifier}): Fetched page {list_pages_fetched}, {len(messages)} IDs added. Total IDs: {len(message_ids)}")

                page_token = response.get('nextPageToken')
                retries = 0 # Reset retries on success
                if not page_token:
                    logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): No more pages. Total IDs fetched: {len(message_ids)}")
                    break # Exit loop

                time.sleep(0.2) # Small delay between list calls

            except HttpError as http_err:
                status_code = http_err.resp.status if hasattr(http_err.resp, 'status') else 'Unknown'
                logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): HTTP error during list(): {status_code} - {http_err}")
                if status_code in [429, 500, 503] and retries < max_list_retries:
                    retries += 1
                    wait_time = UTIL_RETRY_DELAY_SECONDS * (2 ** retries)
                    logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): Retrying list() call ({retries+1}/{max_list_retries+1}) after {wait_time}s...")
                    time.sleep(wait_time)
                     # Optional: Refresh credentials again after a long sleep
                    try:
                        if credentials.expired and credentials.refresh_token: credentials.refresh(Request())
                    except Exception: logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): Ignoring credential refresh error during list retry.")
                    continue # Retry the loop
                elif status_code == 403:
                     logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Permission denied (403) listing messages. Check scopes.")
                     error_message = f"Permission denied (403) listing messages."
                     break # Exit loop on permission error
                else:
                    logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Unrecoverable HTTP error during list() or max retries exceeded.")
                    error_message = f"API Error ({status_code}) listing messages: {http_err}"
                    break # Exit loop on unrecoverable error
            except Exception as e:
                logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Unexpected error during list(): {e}", exc_info=True)
                error_message = f"Unexpected error listing messages: {e}"
                break # Exit loop on unexpected error

        if error_message: # If listing failed, return early
            logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Aborting due to error during message listing.")
            return total_trashed_count, error_message

        if not message_ids:
            logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): No messages found matching query '{query}'. Nothing to trash.")
            return 0, None # Success, but nothing done

        # 4. Batch Trash Messages using batchModify
        logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Preparing to trash {len(message_ids)} messages using batchModify.")

        batch_size = UTIL_BATCH_MODIFY_LIMIT # Use constant
        batch_errors = 0
        max_batch_retries = UTIL_MAX_RETRIES # Use constant

        for batch_index, id_chunk in enumerate(chunk_list(message_ids, batch_size)):
            if not id_chunk: continue

            batch_retries = 0
            current_batch_failed = False
            while batch_retries <= max_batch_retries:
                try:
                    first_id = id_chunk[0]
                    logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Attempting batchModify Batch {batch_index + 1} ({len(id_chunk)} IDs, Attempt {batch_retries + 1}/{max_batch_retries+1}). First ID: {first_id}")
                    # Use batchModify to add TRASH label and remove INBOX
                    body = {'ids': id_chunk, 'addLabelIds': ['TRASH'], 'removeLabelIds': ['INBOX']}
                    service.users().messages().batchModify(userId='me', body=body).execute()

                    logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Batch {batch_index + 1} executed successfully.")
                    total_trashed_count += len(id_chunk)
                    current_batch_failed = False
                    break # Success for this batch

                except HttpError as http_err:
                    status_code = http_err.resp.status if hasattr(http_err.resp, 'status') else 'Unknown'
                    logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): HTTP error during batch {batch_index + 1} execute: {status_code} - {http_err}")
                    current_batch_failed = True
                    if status_code == 403:
                        logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Permission denied (403) on batchModify. Aborting.")
                        error_message = f"Permission denied (403) trashing messages."
                        break # Exit retry loop for this batch
                    elif status_code in [429, 500, 503] and batch_retries < max_batch_retries:
                        batch_retries += 1
                        wait_time = UTIL_RETRY_DELAY_SECONDS * (2 ** batch_retries)
                        logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): Retrying batch {batch_index + 1} ({batch_retries + 1}/{max_batch_retries+1}) after {wait_time}s...")
                        time.sleep(wait_time)
                         # Optional: Refresh creds again?
                        try:
                            if credentials.expired and credentials.refresh_token: credentials.refresh(Request())
                        except Exception: logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): Ignoring credential refresh error during batch retry.")
                        continue # Retry the while loop for this batch
                    else:
                        logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Unrecoverable HTTP error ({status_code}) on batch {batch_index + 1} or max retries exceeded.")
                        break # Exit retry loop for this batch
                except Exception as e:
                    logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Unexpected error during batch {batch_index + 1} execute: {e}", exc_info=True)
                    current_batch_failed = True
                    break # Exit retry loop for this batch

            # After retry loop for one batch
            if current_batch_failed:
                 batch_errors += 1
                 # Set/update error message, but continue to next batch unless it was fatal (like 403)
                 error_message = f"Completed, but encountered errors on {batch_errors} batches (check logs)."
                 if status_code == 403: # If the failure was 403, stop processing further batches
                      break # Exit the outer 'for batch_index...' loop

            # Optional delay between batches
            if batch_index < (len(message_ids) // batch_size) - 1:
                 time.sleep(1.0) # Use a consistent delay

        # 5. Final Result
        logger.info(f"@@@ TRASH QUERY UTIL ({log_identifier}): Finished. Total messages successfully trashed: {total_trashed_count}.")
        if batch_errors > 0:
             logger.warning(f"@@@ TRASH QUERY UTIL ({log_identifier}): Encountered errors on {batch_errors} batches.")
        elif not error_message: # If no batch errors and no listing errors, ensure final error is None
             error_message = None

        return total_trashed_count, error_message

    except Exception as outer_exc:
        # Catch-all for unexpected errors in the setup/flow
        logger.error(f"@@@ TRASH QUERY UTIL ({log_identifier}): Outer unexpected error: {outer_exc}", exc_info=True)
        return total_trashed_count, f"Unexpected utility error: {outer_exc}"