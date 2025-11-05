/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file httputils.c
 * @brief HTTP utility functions built on libcurl.
 *
 * This module provides an abstraction layer over libcurl to simplify HTTP(S)
 * request handling. It supports:
 *
 * - Synchronous and asynchronous requests (via easy and multi handles).
 * - Custom HTTP methods, headers, and payloads.
 * - SSL/TLS configuration (CA certificates, client certs, private keys).
 * - Response buffering through a write callback.
 * - Encapsulation of libcurl handles in domain-specific types (e.g.,
 * gvm_http_t).
 */

#include "httputils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

/**
 * @brief Allocate gvm http multi handler
 *
 * @return gvm http multi handler.
 */
static gvm_http_multi_t *
gvm_http_multi_t_new (void)
{
  return (gvm_http_multi_t *) g_malloc0 (sizeof (struct gvm_http_multi));
}

/**
 * @brief Callback function to store the response.
 *
 * @param ptr Pointer to the delivered data.
 * @param size Size of each data element.
 * @param nmemb Number of data elements.
 * @param userdata Pointer to the user-defined buffer or structure
 *                 where the data will be stored.
 *
 * @return The number of bytes actually handled.
 */
static size_t
store_response_data (void *ptr, size_t size, size_t nmemb, void *userdata)
{
  gvm_http_response_stream_t stream = userdata;
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
 * @brief Allocates and initializes a gvm_http_t structure with a given CURL
 * handle.
 *
 * @param curl_handler  A valid libcurl easy handle to be wrapped. If NULL, the
 * function returns NULL.
 *
 * @return A pointer to an initialized `gvm_http_t` structure on success,
 *         or NULL if the input handle is invalid.
 */
static gvm_http_t *
gvm_http_t_new (CURL *curl_handler)
{
  if (!curl_handler)
    return NULL;

  gvm_http_t *http = g_malloc0 (sizeof (gvm_http_t));
  http->handler = curl_handler;
  return http;
}

/**
 * @brief Frees a gvm_http_t object and its associated CURL handle.
 *
 * @param http Pointer to the gvm_http_t structure to free. Safe to pass NULL.
 */
void
gvm_http_free (gvm_http_t *http)
{
  if (!http)
    return;
  if (http->handler)
    curl_easy_cleanup (http->handler);
  g_free (http);
}

/**
 * @brief Initializes and configures a gvm_http_t object for an HTTP(S) request.
 *
 * This function creates and configures a gvm_http_t structure, encapsulating
 * a libcurl easy handle. It sets the target URL, HTTP method, optional headers,
 * payload, and SSL/TLS credentials (CA certificate, client certificate, and
 * private key). It also registers a write callback to store the server's
 * response into a provided response stream buffer.
 *
 * Note: The returned object must be cleaned up by the caller using
 * `gvm_http_free()` to free all associated resources. The request is not
 * executed by this function — only configured.
 *
 * @param url           The full request URL.
 * @param method        The HTTP method to use (GET, POST, etc.).
 * @param payload       Optional request body for POST or PUT.
 * @param headers       Optional custom headers (gvm_http_headers_t).
 * @param ca_cert       Optional CA certificate for server verification.
 * @param client_cert   Optional client certificate for mutual TLS.
 * @param client_key    Optional client private key for mutual TLS.
 * @param res           Response stream used as the write target during the
 * request.
 *
 * @return A configured gvm_http_t object on success, or NULL on failure.
 */
gvm_http_t *
gvm_http_new (const gchar *url, gvm_http_method_t method, const gchar *payload,
              gvm_http_headers_t *headers, const gchar *ca_cert,
              const gchar *client_cert, const gchar *client_key,
              gvm_http_response_stream_t res)
{
  CURL *curl = curl_easy_init ();
  if (!curl)
    return NULL;

  // Set URL
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, store_response_data);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *) res);

  // Set HTTP headers if provided
  if (headers && headers->custom_headers)
    {
      curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers->custom_headers);
    }

  // Handle SSL CA Certificate
  if (ca_cert)
    {
      struct curl_blob ca_blob = {(void *) ca_cert, strlen (ca_cert),
                                  CURL_BLOB_COPY};
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 1L);
      if (curl_easy_setopt (curl, CURLOPT_CAINFO_BLOB, &ca_blob) != CURLE_OK)
        {
          g_warning ("%s: Failed to set CA certificate", __func__);
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
      struct curl_blob cert_blob = {(void *) client_cert, strlen (client_cert),
                                    CURL_BLOB_COPY};
      struct curl_blob key_blob = {(void *) client_key, strlen (client_key),
                                   CURL_BLOB_COPY};

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
  switch (method)
    {
    case POST:
      if (payload && payload[0] != '\0')
        {
          curl_easy_setopt (curl, CURLOPT_POSTFIELDS, payload);
          curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen (payload));
        }
      break;
    case PUT:
      if (payload && payload[0] != '\0')
        {
          curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "PUT");
          curl_easy_setopt (curl, CURLOPT_POSTFIELDS, payload);
          curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen (payload));
        }
      break;
    case PATCH:
      if (payload && payload[0] != '\0')
        {
          curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "PATCH");
          curl_easy_setopt (curl, CURLOPT_POSTFIELDS, payload);
          curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen (payload));
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

  return gvm_http_t_new (curl);
}

/** @brief Allocate the vt stream struct to hold the response
 *  and the curlm handler
 *
 *  @return The vt stream struct. Must be free with
 * gvm_http_response_stream_free().
 */
gvm_http_response_stream_t
gvm_http_response_stream_new (void)
{
  gvm_http_response_stream_t s;
  s = g_malloc0 (sizeof (struct gvm_http_response_stream));
  s->length = 0;
  s->data = g_malloc0 (s->length + 1);
  s->multi_handler = gvm_http_multi_t_new ();
  return s;
}

/** @brief Cleanup the string struct to hold the response and the
 *  curl multiperform handler
 *
 *  @param s The string struct to be freed
 */
void
gvm_http_response_stream_free (gvm_http_response_stream_t s)
{
  if (s == NULL)
    return;

  g_free (s->data);
  if (s->multi_handler)
    gvm_http_multi_free (s->multi_handler);

  g_free (s);
}

/**
 * @brief Sends a synchronous HTTP(S) request and captures the response.
 *
 * This function performs an HTTP request using libcurl, with the specified
 * method, headers, SSL/TLS credentials, and optional payload. It encapsulates
 * the CURL easy handle and configuration into a `gvm_http_t` structure, which
 * is used to execute the request. The server response is stored in a
 * `gvm_http_response_t` structure, which includes the HTTP status code and
 * response data.
 *
 * If no response stream is provided, an internal one will be allocated and
 * automatically cleaned up. If a stream is provided, the caller is responsible
 * for its cleanup.
 *
 * @param url           The URL to send the request to.
 * @param method        HTTP method to use (e.g., GET, POST, PUT, DELETE).
 * @param payload       Optional request payload for methods like POST or PUT.
 * @param headers       Optional custom headers (`gvm_http_headers_t`).
 * @param ca_cert       Optional CA certificate for server verification.
 * @param client_cert   Optional client certificate for mutual TLS.
 * @param client_key    Optional client private key for mutual TLS.
 * @param response      Optional response stream buffer; if NULL, one will be
 * created.
 *
 * @return A pointer to a `gvm_http_response_t` containing the response data and
 * status. Must be freed with `gvm_http_response_free()`.
 */
gvm_http_response_t *
gvm_http_request (const gchar *url, gvm_http_method_t method,
                  const gchar *payload, gvm_http_headers_t *headers,
                  const gchar *ca_cert, const gchar *client_cert,
                  const gchar *client_key, gvm_http_response_stream_t response)
{
  gvm_http_response_t *http_response = g_malloc0 (sizeof (gvm_http_response_t));
  gboolean internal_stream_allocated = FALSE;

  if (response == NULL)
    {
      response = g_malloc0 (sizeof (struct gvm_http_response_stream));
      response->data = NULL;
      response->length = 0;
      response->multi_handler = NULL;
      internal_stream_allocated = TRUE;
    }

  gvm_http_t *http = gvm_http_new (url, method, payload, headers, ca_cert,
                                   client_cert, client_key, response);
  if (!http)
    {
      http_response->http_status = -1;
      http_response->data =
        g_strdup ("{\"error\": \"Failed to initialize curl request\"}");
      if (internal_stream_allocated)
        gvm_http_response_stream_free (response);
      return http_response;
    }

  http_response->http = http;

  CURLcode result = curl_easy_perform (http->handler);
  if (result == CURLE_OK)
    {
      curl_easy_getinfo (http->handler, CURLINFO_RESPONSE_CODE,
                         &http_response->http_status);
    }
  else
    {
      g_debug ("%s: Error performing CURL request: %s", __func__,
                 curl_easy_strerror (result));
      http_response->http_status = -1;
      http_response->data =
        g_strdup_printf ("{\"error\": \"CURL request failed: %s\"}",
                         curl_easy_strerror (result));
    }

  if (response && response->data)
    {
      http_response->data = g_strdup (response->data);
    }
  else
    {
      http_response->data = g_strdup ("{\"error\": \"Empty response\"}");
    }

  if (internal_stream_allocated)
    {
      gvm_http_response_stream_free (response);
    }

  return http_response;
}

/**
 * @brief Cleans up a gvm_http_response_t structure and associated resources.
 *
 * @param response Pointer to a `gvm_http_response_t` structure to clean up.
 *                 Can safely be NULL.
 */
void
gvm_http_response_free (gvm_http_response_t *response)
{
  if (!response)
    return;

  gvm_http_free (response->http);
  g_free (response->data);
  g_free (response);
}

/**
 * @brief Allocates and initializes a new gvm_http_headers_t structure.
 *
 * @return A pointer to a newly allocated `gvm_http_headers_t` structure.
 */
gvm_http_headers_t *
gvm_http_headers_new (void)
{
  gvm_http_headers_t *headers = g_malloc0 (sizeof (gvm_http_headers_t));
  headers->custom_headers = NULL;
  return headers;
}

/**
 * @brief Adds a custom HTTP header to the headers structure.
 *
 * @param headers A pointer to a `gvm_http_headers_t` structure.
 * @param header The header string to add (e.g., "Content-Type:
 * application/json").
 *
 * @return TRUE if the header was successfully added, FALSE otherwise.
 */
gboolean
gvm_http_add_header (gvm_http_headers_t *headers, const gchar *header)
{
  if (!headers || !header)
    return FALSE;

  struct curl_slist *result =
    curl_slist_append (headers->custom_headers, header);
  if (!result)
    return FALSE;

  headers->custom_headers = result;
  return TRUE;
}

/**
 * @brief Frees memory associated with a gvm_http_headers_t structure.
 *
 * @param headers A pointer to the `gvm_http_headers_t` structure to free.
 *                Can be NULL.
 */
void
gvm_http_headers_free (gvm_http_headers_t *headers)
{
  if (!headers)
    return;

  if (headers->custom_headers)
    curl_slist_free_all (headers->custom_headers);

  g_free (headers);
}

/**
 * @brief Initializes a multi-handle for managing concurrent HTTP(S) requests.
 *
 * @return A pointer to the newly allocated `gvm_http_multi_t` structure,
 *         or NULL if initialization fails.
 */
gvm_http_multi_t *
gvm_http_multi_new ()
{
  gvm_http_multi_t *multi = g_malloc0 (sizeof (gvm_http_multi_t));
  multi->handler = curl_multi_init ();
  multi->headers = gvm_http_headers_new ();

  return multi;
}

/**
 * @brief Adds an HTTP request (easy handle) to a multi-handle session.
 *
 * @param multi The multi-handle session to add the request to.
 * @param http The HTTP request (easy handle wrapper) to add.
 *
 * @return A `gvm_http_multi_result_t` indicating the result of the operation.
 */
gvm_http_multi_result_t
gvm_http_multi_add_handler (gvm_http_multi_t *multi, gvm_http_t *http)
{
  if (!multi || !multi->handler || !http || !http->handler)
    return GVM_HTTP_MULTI_BAD_HANDLE;

  CURLMcode result = curl_multi_add_handle (multi->handler, http->handler);

  switch (result)
    {
    case CURLM_OK:
      return GVM_HTTP_OK;
    case CURLM_BAD_HANDLE:
      return GVM_HTTP_MULTI_BAD_HANDLE;
    case CURLM_INTERNAL_ERROR:
      return GVM_HTTP_MULTI_FAILED;
    default:
      return GVM_HTTP_MULTI_UNKNOWN_ERROR;
    }
}

/**
 * @brief Executes all pending transfers in the given multi-handle session.
 *
 * @param multi Pointer to the multi-handle wrapper structure.
 * @param running_handles Pointer to an integer to store the count of ongoing
 * transfers.
 *
 * @return A `gvm_http_multi_result_t` value indicating the status of the
 * operation.
 *         - GVM_HTTP_OK: Success.
 *         - GVM_HTTP_MULTI_BAD_HANDLE: Invalid or NULL multi-handle.
 *         - GVM_HTTP_MULTI_FAILED: Other failure occurred.
 */
gvm_http_multi_result_t
gvm_http_multi_perform (gvm_http_multi_t *multi, int *running_handles)
{
  if (!multi || !multi->handler)
    return GVM_HTTP_MULTI_BAD_HANDLE;

  CURLMcode result = curl_multi_perform (multi->handler, running_handles);
  switch (result)
    {
    case CURLM_OK:
      return GVM_HTTP_OK;
    case CURLM_BAD_HANDLE:
      return GVM_HTTP_MULTI_BAD_HANDLE;
    default:
      return GVM_HTTP_MULTI_FAILED;
    }
}

/**
 * @brief Polls the multi-handle for activity, waiting up to the specified
 * timeout.
 *
 * @param multi Pointer to the `gvm_http_multi_t` structure containing the
 * multi-handle.
 * @param timeout Maximum time in milliseconds to wait for activity.
 *
 * @return A `gvm_http_multi_result_t` indicating the result of the poll
 * operation:
 *         - GVM_HTTP_OK: Polling succeeded.
 *         - GVM_HTTP_MULTI_BAD_HANDLE: Invalid or NULL multi-handle.
 *         - GVM_HTTP_MULTI_FAILED: Polling failed due to an error.
 */
gvm_http_multi_result_t
gvm_http_multi_poll (gvm_http_multi_t *multi, int timeout)
{
  if (!multi || !multi->handler)
    return GVM_HTTP_MULTI_BAD_HANDLE;

  CURLMcode poll_result =
    curl_multi_poll (multi->handler, NULL, 0, timeout, NULL);
  switch (poll_result)
    {
    case CURLM_OK:
      return GVM_HTTP_OK;
    case CURLM_BAD_HANDLE:
      return GVM_HTTP_MULTI_BAD_HANDLE;
    default:
      return GVM_HTTP_MULTI_FAILED;
    }
}

/**
 * @brief Removes a gvm_http_t handler from a multi-handle and frees its
 * resources.
 *
 * @param multi Pointer to the `gvm_http_multi_t` multi-handle session.
 * @param http Pointer to the `gvm_http_t` object to remove and free.
 */
void
gvm_http_multi_handler_free (gvm_http_multi_t *multi, gvm_http_t *http)
{
  if (!multi || !multi->handler || !http || !http->handler)
    {
      g_warning ("%s: Invalid multi-handle or http handle", __func__);
      return;
    }

  curl_multi_remove_handle (multi->handler, http->handler);

  gvm_http_free (http);
}

/**
 * @brief Cleans up a CURL multi-handle session and its associated resources.
 *
 * @param multi The multi-handle wrapper to clean up. If NULL or uninitialized,
 *        the function returns safely without performing any cleanup.
 */
void
gvm_http_multi_free (gvm_http_multi_t *multi)
{
  if (!multi)
    return;

  if (!multi->handler)
    {
      g_free (multi);
      return;
    }

  int queued = 0;
  CURLMsg *msg;

  /* Remove completed easy handles */
  while ((msg = curl_multi_info_read (multi->handler, &queued)))
    {
      if (msg->msg == CURLMSG_DONE)
        {
          void *easy_handle = msg->easy_handle;
          curl_multi_remove_handle (multi->handler, easy_handle);
          curl_easy_cleanup (easy_handle);
        }
      else
        {
          g_warning ("%s: Not possible to clean up a curl handle", __func__);
        }
    }

  /* Free custom headers */
  if (multi->headers)
    {
      gvm_http_headers_free (multi->headers);
      multi->headers = NULL;
    }

  /* Cleanup multi handle */
  curl_multi_cleanup (multi->handler);
  multi->handler = NULL;

  g_free (multi);
}

/** @brief Reinitialize the string struct to hold the response
 *
 *  @param s The string struct to be reset
 */
void
gvm_http_response_stream_reset (gvm_http_response_stream_t s)
{
  if (s)
    {
      g_free (s->data);
      s->length = 0;
      s->data = g_malloc0 (s->length + 1);
    }
}
