/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for communication with an HTTP scanner.
 */

#ifndef _GVM_HTTP_SCANNER_HTTP_SCANNER_H
#define _GVM_HTTP_SCANNER_HTTP_SCANNER_H

#include "../util/jsonpull.h"

#include <glib.h>
#include <stdio.h>
#include <time.h>

/** @brief HTTP scanner Errors. */
enum HTTP_SCANNER_ERROR
{
  HTTP_SCANNER_INVALID_OPT,
  HTTP_SCANNER_NOT_INITIALIZED,
  HTTP_SCANNER_INVALID_VALUE,
  HTTP_SCANNER_ERROR,
  HTTP_SCANNER_OK,
};

/** @brief options for the connector builder. */
enum HTTP_SCANNER_CONNECTOR_OPTS
{
  HTTP_SCANNER_CA_CERT,
  HTTP_SCANNER_CERT,
  HTTP_SCANNER_KEY,
  HTTP_SCANNER_API_KEY,
  HTTP_SCANNER_PROTOCOL,
  HTTP_SCANNER_HOST,
  HTTP_SCANNER_SCAN_ID,
  HTTP_SCANNER_PORT,
  HTTP_SCANNER_SCAN_PREFIX,
};

/** @brief Members of an HTTP scanner result. */
enum HTTP_SCANNER_RESULT_MEMBER_STRING
{
  TYPE,
  IP_ADDRESS,
  HOSTNAME,
  OID,
  PORT,
  MESSAGE,
  DETAIL_NAME,
  DETAIL_VALUE,
  DETAIL_SOURCE_NAME,
  DETAIL_SOURCE_TYPE,
  DETAIL_SOURCE_DESCRIPTION,
};

/** @brief Members of an HTTP scanner result. */
enum HTTP_SCANNER_RESULT_MEMBER_INT
{
  ID,
};

/** @brief Openvasd scan status. */
typedef enum
{
  HTTP_SCANNER_SCAN_STATUS_ERROR = -2,  /**< Error status. */
  HTTP_SCANNER_SCAN_STATUS_FAILED = -1, /**< Failed status. */
  HTTP_SCANNER_SCAN_STATUS_STORED,      /**< Stored status. */
  HTTP_SCANNER_SCAN_STATUS_REQUESTED,   /**< Queued status. */
  HTTP_SCANNER_SCAN_STATUS_RUNNING,     /**< Running status. */
  HTTP_SCANNER_SCAN_STATUS_STOPPED,     /**< Stopped status. */
  HTTP_SCANNER_SCAN_STATUS_SUCCEEDED,   /**< Succeeded status. */
} http_scanner_status_t;

/** @brief Struct to hold an HTTP scanner response. */
struct http_scanner_response
{
  long code;     /**< HTTP code response. */
  gchar *body;   /**< String containing the body response. */
  gchar *header; /**< A header value. */
};

/** @brief Struct to hold an HTTP scanner scan status. */
struct http_scanner_scan_status
{
  time_t start_time;
  time_t end_time;
  int progress;
  http_scanner_status_t status;
  long response_code;
};

/** @brief Struct to hold an scan result. */
struct http_scanner_result
{
  unsigned long id;
  gchar *type;
  gchar *ip_address;
  gchar *hostname;
  gchar *oid;
  gchar *port;
  gchar *message;
  gchar *detail_name;
  gchar *detail_value;
  gchar *detail_source_type;
  gchar *detail_source_name;
  gchar *detail_source_description;
};

/** @brief Struct holding options for HTTP scanner parameters. */
struct http_scanner_param
{
  gchar *id;          /**< Parameter id. */
  gchar *name;        /**< Parameter name. */
  gchar *defval;      /**< Default value. */
  gchar *description; /**< Description. */
  gchar *type;        /**< Parameter type. */
  int mandatory;      /**< If mandatory. */
};

/**
 * @brief HTTP Scanner Request methods
 */
typedef enum
{
  HTTP_SCANNER_GET,
  HTTP_SCANNER_POST,
  HTTP_SCANNER_PUT,
  HTTP_SCANNER_DELETE,
  HTTP_SCANNER_HEAD,
  HTTP_SCANNER_PATCH
} http_scanner_method_t;

typedef enum HTTP_SCANNER_CONNECTOR_OPTS http_scanner_conn_opt_t;

typedef enum HTTP_SCANNER_RESULT_MEMBER_INT http_scanner_result_member_int_t;

typedef enum HTTP_SCANNER_RESULT_MEMBER_STRING
  http_scanner_result_member_string_t;

typedef enum HTTP_SCANNER_ERROR http_scanner_error_t;

typedef struct http_scanner_connector *http_scanner_connector_t;

typedef struct http_scanner_response *http_scanner_resp_t;

typedef struct http_scanner_result *http_scanner_result_t;

typedef struct http_scanner_scan_status *http_scanner_scan_status_t;

typedef struct http_scanner_param http_scanner_param_t;

http_scanner_connector_t
http_scanner_connector_new (void);

http_scanner_error_t
http_scanner_connector_builder (http_scanner_connector_t,
                                http_scanner_conn_opt_t, const void *);

http_scanner_error_t http_scanner_connector_free (http_scanner_connector_t);

void http_scanner_response_cleanup (http_scanner_resp_t);

http_scanner_resp_t
http_scanner_init_request_multi (http_scanner_connector_t, const gchar *);

int
http_scanner_process_request_multi (http_scanner_connector_t, int);

http_scanner_resp_t http_scanner_get_version (http_scanner_connector_t);

http_scanner_resp_t
http_scanner_create_scan (http_scanner_connector_t, gchar *);

http_scanner_resp_t http_scanner_start_scan (http_scanner_connector_t);

http_scanner_resp_t http_scanner_get_scan_status (http_scanner_connector_t);

http_scanner_resp_t http_scanner_stop_scan (http_scanner_connector_t);

http_scanner_resp_t http_scanner_delete_scan (http_scanner_connector_t);

http_scanner_resp_t
http_scanner_get_scan_results (http_scanner_connector_t, long, long);

http_scanner_result_t
http_scanner_result_new (unsigned long, gchar *, gchar *, gchar *, gchar *,
                         gchar *, gchar *, gchar *, gchar *, gchar *, gchar *,
                         gchar *, gchar *);

void http_scanner_result_free (http_scanner_result_t);

char *http_scanner_get_result_member_str (http_scanner_result_t,
                                          http_scanner_result_member_string_t);

int http_scanner_get_result_member_int (http_scanner_result_t,
                                        http_scanner_result_member_int_t);

int
http_scanner_parsed_results (http_scanner_connector_t, unsigned long,
                             unsigned long, GSList **);

http_scanner_scan_status_t
  http_scanner_parsed_scan_status (http_scanner_connector_t);

int http_scanner_get_scan_progress (http_scanner_connector_t);

http_scanner_resp_t http_scanner_get_health_alive (http_scanner_connector_t);

http_scanner_resp_t http_scanner_get_health_ready (http_scanner_connector_t);

http_scanner_resp_t http_scanner_get_health_started (http_scanner_connector_t);

http_scanner_resp_t
  http_scanner_get_scan_preferences (http_scanner_connector_t);

int
http_scanner_parsed_scans_preferences (http_scanner_connector_t, GSList **);

void
http_scanner_param_free (http_scanner_param_t *);

char *
http_scanner_param_id (http_scanner_param_t *);

char *
http_scanner_param_name (http_scanner_param_t *);

char *
http_scanner_param_desc (http_scanner_param_t *);

int
http_scanner_param_mandatory (http_scanner_param_t *);

char *
http_scanner_param_type (http_scanner_param_t *);

char *
http_scanner_param_default (http_scanner_param_t *);

void http_scanner_reset_stream (http_scanner_connector_t);

gchar *http_scanner_stream_str (http_scanner_connector_t);

size_t http_scanner_stream_len (http_scanner_connector_t);

http_scanner_resp_t
http_scanner_send_request (http_scanner_connector_t, http_scanner_method_t,
                           const gchar *, const gchar *, const gchar *);

#endif /* not _GVM_HTTP_SCANNER_HTTP_SCANNER_H */