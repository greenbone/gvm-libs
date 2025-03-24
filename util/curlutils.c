/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file curlutils.c
 * @brief Utility functions for handling HTTP(S) requests using libcurl.
 *
 * This file provides a set of wrappers and helpers to simplify the use of libcurl
 * for sending HTTP and HTTPS requests. It includes support for:
 *
 * - Single and multi-handle CURL operations.
 * - Custom headers and payloads.
 * - SSL certificate handling (CA, client cert, and key).
 * - Asynchronous/multiplexed request support via CURLM.
 * - Response buffering via callback mechanism.
 */


#include "curlutils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

/**
 * @brief Callback function to store the response.
 * This function is used with libcurl to dynamically store response data.
 */
static size_t
curlutils_response_callback (void *ptr, size_t size, size_t nmemb, void *userdata)
{
  curlutils_response_stream_t stream = userdata;
  size_t new_len = stream->length + size * nmemb;
  gchar *temp_ptr = g_realloc (stream->data, new_len + 1);

  if (!temp_ptr)
    return 0;

  stream->data = temp_ptr;
  memcpy (stream->data + stream->length, ptr, size * nmemb);
  stream->data[new_len] = '\0';
  stream->length = new_len;

  return size * nmemb;
}

/**
 * @brief Initializes and configures a CURL easy handle for an HTTP(S) request.
 *
 * This function sets up a CURL handle with the specified URL, HTTP method,
 * optional headers, payload, and SSL/TLS credentials (CA certificate,
 * client certificate, and private key). It also configures the write callback
 * to store the server's response in a provided response stream structure.
 *
 * The caller is responsible for performing and cleaning up the CURL request.
 *
 * @param url           The full request URL.
 * @param method        The HTTP method to use (GET, POST, etc.).
 * @param payload       The optional request body (used with POST/PUT).
 * @param headers       A list of custom headers to include in the request.
 * @param ca_cert       Optional CA certificate for server validation.
 * @param client_cert   Optional client certificate for mutual TLS.
 * @param client_key    Optional client private key for mutual TLS.
 * @param res           Pointer to a response stream structure to capture
 *                      the response body.
 *
 * @return A configured CURL easy handle on success, or NULL on failure.
 */
CURL *
curlutils_init_request (const gchar *url, curlutils_method_t method,
                        const gchar *payload, struct curl_slist *headers,
                        const gchar *ca_cert, const gchar *client_cert,
                        const gchar *client_key, curlutils_response_stream_t res)
{
    CURL *curl = curl_easy_init ();
    if (!curl) return NULL;

    // Set URL
    curl_easy_setopt (curl, CURLOPT_URL, url);
    curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, curlutils_response_callback);
    curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)res);

    // Set HTTP headers if provided
    if (headers)
      {
        curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
      }

    // Handle SSL CA Certificate
    if (ca_cert)
      {
        struct curl_blob ca_blob = { (void *)ca_cert, strlen (ca_cert), CURL_BLOB_COPY };
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 1L);
        if (curl_easy_setopt (curl, CURLOPT_CAINFO_BLOB, &ca_blob) != CURLE_OK)
          {
            g_warning("%s: Failed to set CA certificate", __func__);
            curl_easy_cleanup (curl);
            return NULL;
          }
      }
    else
    {
        // Accept insecure connections if no CA cert is provided
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt (curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
        g_debug ("%s: Server certificate verification disabled.", __func__);
    }

    // Handle Client Certificate & Private Key for authentication
    if (client_cert != NULL && client_key != NULL)
      {
        struct curl_blob cert_blob = { (void *)client_cert, strlen(client_cert), CURL_BLOB_COPY };
        struct curl_blob key_blob = { (void *)client_key, strlen(client_key), CURL_BLOB_COPY };

        if (curl_easy_setopt (curl, CURLOPT_SSLCERT_BLOB, &cert_blob) != CURLE_OK)
          {
            g_warning ("%s: Failed to set client certificate", __func__);
            curl_easy_cleanup (curl);
            return NULL;
          }

        if (curl_easy_setopt (curl, CURLOPT_SSLKEY_BLOB, &key_blob) != CURLE_OK)
          {
            g_warning ("%s: Failed to set client private key", __func__);
            curl_easy_cleanup (curl);
            return NULL;
         }
      }

    // Handle HTTP Method
    switch (method) {
        case POST:
            if (payload && payload[0] != '\0')
              {
                curl_easy_setopt (curl, CURLOPT_POSTFIELDS, payload);
                curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen(payload));
              }
            break;
        case PUT:
            if (payload && payload[0] != '\0')
              {
                curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt (curl, CURLOPT_POSTFIELDS, payload);
                curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen(payload));
              }
            break;
        case DELETE:
            curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case HEAD:
            curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "HEAD");
            break;
        case GET:
        default:
            curl_easy_setopt (curl, CURLOPT_HTTPGET, 1L);
            break;
    }

    return curl;
}

/**
 * @brief Frees memory allocated for a curlutils response stream.
 *
 * This function safely frees the response data, associated custom headers,
 * and the CURL multi-handle stored in the given response stream structure.
 * It also frees the response stream structure itself.
 *
 * @param res The response stream to clean up. Can be NULL.
 */
static void
curlutils_response_stream_cleanup (curlutils_response_stream_t res)
{
  if (!res) return;

  g_free (res->data);
  if (res->multi_handle)
    {
      curl_slist_free_all (res->multi_handle->custom_headers);
      curl_multi_cleanup (res->multi_handle->handle);
      g_free (res->multi_handle);
  }
  g_free (res);
}

/**
 * @brief Sends a synchronous HTTP request using libcurl and captures the
 * response.
 *
 * This function performs a CURL request with the specified parameters,
 * including HTTP method, headers, SSL certificates, and optional payload. The
 * response data is stored in a `curlutils_response_t` structure, which includes
 * the HTTP status code, response body, and the CURL handle.
 *
 * If a `curlutils_response_stream_t` is not provided, an internal one is
 * allocated and cleaned up automatically. If provided, the caller is
 * responsible for cleanup.
 *
 * @param url The URL to send the request to.
 * @param method The HTTP method to use (GET, POST, PUT, DELETE, HEAD).
 * @param payload Optional payload for POST or PUT requests.
 * @param headers Optional list of custom headers.
 * @param ca_cert Optional CA certificate for SSL verification.
 * @param client_cert Optional client certificate for authentication.
 * @param client_key Optional client private key for authentication.
 * @param response Optional response stream to capture raw data. If NULL, an
 * internal stream is used.
 *
 * @return A `curlutils_response_t *` pointer containing the response data and
 * status.
 */
curlutils_response_t *
curlutils_request (const gchar *url, curlutils_method_t method,
                   const gchar *payload, struct curl_slist *headers,
                   const gchar *ca_cert, const gchar *client_cert,
                   const gchar *client_key,
                   curlutils_response_stream_t response)
{
  curlutils_response_t *curl_response = g_malloc0 (sizeof (curlutils_response_t));
  gboolean internal_stream_allocated = FALSE;

  if (response == NULL)
    {
      response = g_malloc0 (sizeof (struct curlutils_response_stream));
      response->data = NULL;
      response->length = 0;
      response->multi_handle = NULL;
      internal_stream_allocated = TRUE;
    }

  CURL *curl = curlutils_init_request (url, method, payload, headers,
                                       ca_cert, client_cert, client_key, response);
  if (!curl)
    {
      curl_response->http_status = -1;
      curl_response->data = g_strdup ("{\"error\": \"Failed to initialize curl request\"}");
      if (internal_stream_allocated)
        curlutils_response_stream_cleanup (response);
      return curl_response;
    }

  curl_response->curl_handle = curl;

  CURLcode result = curl_easy_perform (curl);
  if (result == CURLE_OK)
    {
      curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &curl_response->http_status);
    }
  else
    {
      g_warning ("%s: Error performing CURL request: %s", __func__, curl_easy_strerror (result));
      curl_response->http_status = -1;
      curl_response->data = g_strdup_printf (
        "{\"error\": \"CURL request failed: %s\"}",
        curl_easy_strerror (result)
      );
    }

  if (response && response->data)
    {
      curl_response->data = g_strdup (response->data);
    }
  else
    {
      curl_response->data = g_strdup ("{\"error\": \"Empty response\"}");
    }

  if (internal_stream_allocated)
    {
      curlutils_response_stream_cleanup (response);
    }

  return curl_response;
}

/**
 * @brief Cleans up a CURL request and frees associated response data.
 *
 * @param response Pointer to a `curlutils_response_t` structure to clean up.
 */
void
curlutils_cleanup (curlutils_response_t *response)
{
  if (response->curl_handle)
    {
      curl_easy_cleanup (response->curl_handle);
      response->curl_handle = NULL;
    }
  g_free (response->data);
  response->data = NULL;
  response->size = 0;
}

/**
 * @brief Initialize a multi-handle for concurrent requests.
 *
 * @return A pointer to a newly allocated `curlutils_multi_t` structure.
 */
curlutils_multi_t *
curlutils_multi_init ()
{
  curlutils_multi_t *multi = g_malloc0 (sizeof(curlutils_multi_t));
  multi->handle = curl_multi_init ();
  multi->custom_headers = NULL;

  return multi;
}


/**
 * @brief Add an easy handle to a multi-handle session.
 *
 * @param multi The multi-handler.
 * @param easy The CURL easy handle.
 * @return CURLMcode indicating success or failure.
 */
CURLMcode
curlutils_multi_add_handle (curlutils_multi_t *multi, CURL *easy)
{
  return curl_multi_add_handle (multi->handle, easy);
}


/**
 * @brief Executes a multi-handle CURL request.
 *
 * Performs all currently pending transfers in the given multi-handle session.
 * It is typically called repeatedly until all transfers are complete.
 *
 * @param multi The multi-handle session wrapper.
 * @param running_handles Pointer to an integer that will receive the number of
 *        still-running transfers after this function returns.
 *
 * @return CURLMcode indicating success or failure (e.g., CURLM_OK).
 */
CURLMcode
curlutils_multi_perform (curlutils_multi_t *multi, int *running_handles)
{
  if (!multi || !multi->handle)
    return CURLM_BAD_HANDLE;

  return curl_multi_perform (multi->handle, running_handles);
}

/**
 * @brief Removes an easy handle from a multi handle and cleans it up properly.
 *
 * @param multi The multi-handle that contains the easy handle.
 * @param easy The CURL easy handle to remove and clean.
 */
void
curlutils_remove_handle (curlutils_multi_t *multi, CURL *easy)
{
  if (!multi || !multi->handle || !easy)
    {
      g_warning( "%s: Invalid multi-handle or easy handle", __func__);
      return;
    }

  curl_multi_remove_handle (multi->handle, easy);

  curl_easy_cleanup (easy);
}

/**
 * @brief Cleans up a CURL multi-handle session and its associated resources.
 *
 * @param multi The multi-handle wrapper to clean up. If NULL or uninitialized,
 *        the function safely returns.
 */
void
curlutils_multi_cleanup (curlutils_multi_t *multi)
{
  if (!multi || !multi->handle)
    return;

  int queued = 0;
  CURLMsg *msg;

  /* Remove completed easy handles */
  while ((msg = curl_multi_info_read (multi->handle, &queued)))
    {
      if (msg->msg == CURLMSG_DONE)
        {
          CURL *easy_handle = msg->easy_handle;
          curl_multi_remove_handle (multi->handle, easy_handle);
          curl_easy_cleanup (easy_handle);
        }
      else
        {
          g_warning("%s: Not possible to clean up a curl handle", __func__);
        }
    }

  /* Free custom headers */
  if (multi->custom_headers)
    {
      curl_slist_free_all(multi->custom_headers);
      multi->custom_headers = NULL;
    }

  /* Cleanup multi handle */
  curl_multi_cleanup (multi->handle);
  multi->handle = NULL;

  g_free (multi);
}

/**
 * @brief Appends a new HTTP header to an existing list of headers.
 *
 * @param headers The current list of headers, or NULL to start a new list.
 * @param header The HTTP header string to append.
 *
 * @return The updated list of headers including the new entry.
 */
struct curl_slist *
curlutils_add_header (struct curl_slist *headers, const gchar *header)
{
  return curl_slist_append (headers, header);
}

/**
 * @brief Frees a list of HTTP headers.
 *
 * This function releases the memory allocated for a curl_slist
 * containing HTTP headers using libcurl’s curl_slist_free_all().
 *
 * @param headers The list of headers to free. Can be NULL.
 */
void
curlutils_cleanup_headers (struct curl_slist *headers)
{
  curl_slist_free_all (headers);
}
