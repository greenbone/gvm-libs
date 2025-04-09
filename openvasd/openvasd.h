/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Openvas Daemon communication.
 */

#ifndef _GVM_OPENVASD_H
#define _GVM_OPENVASD_H

#include "../base/nvti.h"
#include "../util/jsonpull.h"

#include <glib.h>
#include <stdio.h>
#include <time.h>

/** @brief Struct to hold an scan result */
struct openvasd_result
{
  unsigned long id;
  gchar *type;
  gchar *ip_address;
  gchar *hostname;
  gchar *oid;
  int port;
  gchar *protocol;
  gchar *message;
  gchar *detail_name;
  gchar *detail_value;
  gchar *detail_source_type;
  gchar *detail_source_name;
  gchar *detail_source_description;
};

/** @brief Openvasd Errors */
enum OPENVASD_ERROR
{
  OPENVASD_INVALID_OPT,
  OPENVASD_NOT_INITIALIZED,
  OPENVASD_INVALID_VALUE,
  OPENVASD_ERROR,
  OPENVASD_OK,
};

/** @brief Openvasd options for the connector builder */
enum OPENVASD_CONNECTOR_OPTS
{
  OPENVASD_CA_CERT,
  OPENVASD_CERT,
  OPENVASD_KEY,
  OPENVASD_API_KEY,
  OPENVASD_PROTOCOL,
  OPENVASD_HOST,
  OPENVASD_SCAN_ID,
  OPENVASD_PORT,
};

enum OPENVASD_RESULT_MEMBER_STRING
{
  TYPE,
  IP_ADDRESS,
  HOSTNAME,
  OID,
  PROTOCOL,
  MESSAGE,
  DETAIL_NAME,
  DETAIL_VALUE,
  DETAIL_SOURCE_NAME,
  DETAIL_SOURCE_TYPE,
  DETAIL_SOURCE_DESCRIPTION,
};

enum OPENVASD_RESULT_MEMBER_INT
{
  ID,
  PORT,
};

/**
 * @brief Openvasd scan status.
 */
typedef enum
{
  OPENVASD_SCAN_STATUS_ERROR = -2,  /**< Error status. */
  OPENVASD_SCAN_STATUS_FAILED = -1, /**< Failed status. */
  OPENVASD_SCAN_STATUS_STORED,      /**< Stored status */
  OPENVASD_SCAN_STATUS_REQUESTED,   /**< Queued status */
  OPENVASD_SCAN_STATUS_RUNNING,     /**< Running status. */
  OPENVASD_SCAN_STATUS_STOPPED,     /**< Stopped status. */
  OPENVASD_SCAN_STATUS_SUCCEEDED,   /**< Succeeded status */
} openvasd_status_t;

struct openvasd_response
{
  long code;     /**< HTTP code response. */
  gchar *body;   /**< String containing the body response. */
  gchar *header; /**< A header value. */
};

struct openvasd_scan_status
{
  time_t start_time;
  time_t end_time;
  int progress;
  openvasd_status_t status;
  long response_code;
};

typedef struct
{
  int start;    /**< Start interval. */
  int end;      /**< End interval. */
  const gchar *titles; /**< Graph title. */
} openvasd_get_performance_opts_t;

typedef struct openvasd_response *openvasd_resp_t;

typedef enum OPENVASD_RESULT_MEMBER_INT openvasd_result_member_int_t;

typedef enum OPENVASD_RESULT_MEMBER_STRING openvasd_result_member_string_t;

typedef enum OPENVASD_CONNECTOR_OPTS openvasd_conn_opt_t;

typedef enum OPENVASD_ERROR openvasd_error_t;

typedef struct openvasd_result *openvasd_result_t;

typedef struct openvasd_connector *openvasd_connector_t;

typedef struct openvasd_scan_status *openvasd_scan_status_t;

// Functions to build/free request data
openvasd_connector_t
openvasd_connector_new (void);

openvasd_error_t
openvasd_connector_builder (openvasd_connector_t, openvasd_conn_opt_t,
                            const void *);

openvasd_error_t openvasd_connector_free (openvasd_connector_t);

void openvasd_response_cleanup (openvasd_resp_t);

// Requests
openvasd_resp_t openvasd_get_version (openvasd_connector_t);

openvasd_resp_t openvasd_get_vts (openvasd_connector_t);

openvasd_resp_t
openvasd_start_scan (openvasd_connector_t, gchar *);

openvasd_resp_t openvasd_stop_scan (openvasd_connector_t);

openvasd_resp_t openvasd_delete_scan (openvasd_connector_t);

openvasd_resp_t
openvasd_get_scan_results (openvasd_connector_t, long, long);

openvasd_result_t
openvasd_result_new (unsigned long, gchar *, gchar *, gchar *, gchar *, int,
                     gchar *, gchar *, gchar *, gchar *, gchar *, gchar *,
                     gchar *);

void openvasd_result_free (openvasd_result_t);

char *openvasd_get_result_member_str (openvasd_result_t,
                                      openvasd_result_member_string_t);

int openvasd_get_result_member_int (openvasd_result_t,
                                    openvasd_result_member_int_t);

int
openvasd_parsed_results (openvasd_connector_t, unsigned long, unsigned long,
                         GSList **);

openvasd_resp_t openvasd_get_scan_status (openvasd_connector_t);

openvasd_scan_status_t openvasd_parsed_scan_status (openvasd_connector_t);

int openvasd_get_scan_progress (openvasd_connector_t);

openvasd_resp_t openvasd_get_health_alive (openvasd_connector_t);

openvasd_resp_t openvasd_get_health_ready (openvasd_connector_t);

openvasd_resp_t openvasd_get_health_started (openvasd_connector_t);

openvasd_resp_t openvasd_get_performance (openvasd_connector_t,
                                          openvasd_get_performance_opts_t);
int
openvasd_parsed_performance (openvasd_connector_t,
                             openvasd_get_performance_opts_t, gchar **,
                             gchar **err);

/* Scanner preferences */

typedef struct openvasd_param openvasd_param_t;

openvasd_resp_t openvasd_get_scan_preferences (openvasd_connector_t);

int
openvasd_parsed_scans_preferences (openvasd_connector_t, GSList **);

void
openvasd_param_free (openvasd_param_t *);

char *
openvasd_param_id (openvasd_param_t *);

char *
openvasd_param_name (openvasd_param_t *);

char *
openvasd_param_desc (openvasd_param_t *);

int
openvasd_param_mandatory (openvasd_param_t *);

char *
openvasd_param_type (openvasd_param_t *);

char *
openvasd_param_default (openvasd_param_t *);

/* Target builder */
typedef struct openvasd_target openvasd_target_t;

typedef struct openvasd_vt_single openvasd_vt_single_t;

typedef struct openvasd_credential openvasd_credential_t;

openvasd_target_t *
openvasd_target_new (const gchar *, const gchar *, const gchar *, const gchar *,
                     int, int);

void
openvasd_target_set_finished_hosts (openvasd_target_t *, const gchar *);

void
openvasd_target_add_alive_test_methods (openvasd_target_t *, gboolean, gboolean,
                                        gboolean, gboolean, gboolean);

void
openvasd_target_free (openvasd_target_t *);

openvasd_credential_t *
openvasd_credential_new (const gchar *, const gchar *, const gchar *);

void
openvasd_credential_set_auth_data (openvasd_credential_t *, const gchar *,
                                   const gchar *);
void
openvasd_credential_free (openvasd_credential_t *);

void
openvasd_target_add_credential (openvasd_target_t *, openvasd_credential_t *);

openvasd_vt_single_t *
openvasd_vt_single_new (const gchar *);

void
openvasd_vt_single_free (openvasd_vt_single_t *);

void
openvasd_vt_single_add_value (openvasd_vt_single_t *, const gchar *,
                              const gchar *);

char *
openvasd_build_scan_config_json (openvasd_target_t *, GHashTable *, GSList *);

/* VT stream */
openvasd_resp_t openvasd_get_vt_stream_init (openvasd_connector_t);

int openvasd_get_vt_stream (openvasd_connector_t);

void openvasd_reset_vt_stream (openvasd_connector_t);

char *openvasd_vt_stream_str (openvasd_connector_t);

size_t openvasd_vt_stream_len (openvasd_connector_t);

nvti_t *
openvasd_parse_vt (gvm_json_pull_parser_t *, gvm_json_pull_event_t *);

#endif
