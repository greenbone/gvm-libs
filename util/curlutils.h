/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file curlutils.h
 * @brief Utility functions and data structures for performing HTTP(S) requests using libcurl.
 *
 * This module provides a set of helper functions and abstractions around libcurl,
 * simplifying both synchronous and asynchronous (multi) HTTP(S) request handling.
 * It supports features such as:
 * - Custom headers
 * - SSL/TLS certificate and key authentication
 * - Response data accumulation and parsing
 * - Cleanup of libcurl resources
 *
 * The main data structures include:
 * - curlutils_response_t: represents the result of a request.
 * - curlutils_response_stream_t: used to accumulate response data with write callbacks.
 * - curlutils_multi_t: wraps libcurl's CURLM multi-handle for concurrent transfers.
 */

#ifndef CURLUTILS_H
#define CURLUTILS_H

#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <glib.h>

/**
 * @brief Request methods
 */
typedef enum {
  GET,
  POST,
  PUT,
  DELETE,
  HEAD
} curlutils_method_t;

/**
 * @brief Wraps a CURLM * handler and the custom headers.
 */
typedef struct curlutils_multi
{
  CURLM *handle; ///< Pointer to the CURL multi-handle used for asynchronous
                 ///< or multi-transfer operations.

  struct curl_slist *custom_headers; ///< List of custom headers associated
                                     ///< with the multi-handle.
} curlutils_multi_t;

/**
 * @brief Defines a struct for storing the response and curl multi-handler.
 */
typedef struct curlutils_response_stream
{
  gchar *data; ///< Pointer to the accumulated response data buffer.

  size_t length; ///< Length of the response data buffer.

  curlutils_multi_t *multi_handle; ///< Pointer to the associated curl
                                   ///< multi-handle and headers.
} curlutils_response_stream;

typedef struct curlutils_response_stream *curlutils_response_stream_t;

/**
 * @brief Represents the result of a curl request.
 */
typedef struct {
  gchar *data; ///< The actual response content as a string.

  gsize size; ///< Size of the response content.

  glong http_status; ///< HTTP status code returned by the server.

  CURL *curl_handle; ///< CURL easy handle used for the request.
} curlutils_response_t;

CURL *
curlutils_init_request (const gchar *url, curlutils_method_t method,
                        const gchar *payload, struct curl_slist *headers,
                        const gchar *ca_cert, const gchar *client_cert,
                        const gchar *client_key, curlutils_response_stream_t res);

curlutils_response_t *
curlutils_request (const gchar *url, curlutils_method_t method, const gchar *payload,
                   struct curl_slist *headers, const gchar *ca_cert,
                   const gchar *client_cert, const gchar *client_key,
                   curlutils_response_stream_t response);

struct curl_slist *
curlutils_add_header (struct curl_slist *headers, const gchar *header);

void
curlutils_cleanup_headers (struct curl_slist *headers);

void
curlutils_cleanup (curlutils_response_t *response);

curlutils_multi_t *
curlutils_multi_init (void);

CURLMcode
curlutils_multi_add_handle (curlutils_multi_t *multi, CURL *easy);

CURLMcode
curlutils_multi_perform (curlutils_multi_t *multi, int *running_handles);

void
curlutils_remove_handle (curlutils_multi_t *multi, CURL *easy);

void
curlutils_multi_cleanup (curlutils_multi_t *multi);

#endif //CURLUTILS_H
