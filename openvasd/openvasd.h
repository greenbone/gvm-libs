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

#include <glib.h>
#include <time.h>

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

enum OPENVASD_ERROR
{
  OPENVASD_INVALID_OPT,
  OPENVASD_NOT_INITIALIZED,
  OPENVASD_INVALID_VALUE,
  OPENVASD_ERROR,
  OPENVASD_OK,
};

enum OPENVASD_CONNECTOR_OPTS
{
  OPENVASD_CA_CERT,
  OPENVASD_CERT,
  OPENVASD_KEY,
  OPENVASD_API_KEY,
  OPENVASD_SERVER,
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
  OPENVASD_SCAN_STATUS_FAILED = -1, /**< Error status. */
  OPENVASD_SCAN_STATUS_STORED,      /**< Stored status */
  OPENVASD_SCAN_STATUS_REQUESTED,   /**< Queued status */
  OPENVASD_SCAN_STATUS_RUNNING,     /**< Running status. */
  OPENVASD_SCAN_STATUS_STOPPED,     /**< Stopped status. */
  OPENVASD_SCAN_STATUS_SUCCEEDED,   /**< Succeeded status */
} openvasd_status_t;

struct openvasd_response
{
  long code;  // HTTP code response
  char *body; // String containing the body response
};

struct openvasd_scan_status
{
  time_t start_time;
  time_t end_time;
  int progress;
  openvasd_status_t status;
};

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
openvasd_connector_builder (openvasd_connector_t *, openvasd_conn_opt_t,
                            const void *);

openvasd_error_t
openvasd_connector_free (openvasd_connector_t *);

void openvasd_response_free (openvasd_resp_t);

// Requests
openvasd_resp_t
openvasd_get_version (openvasd_connector_t *);

openvasd_resp_t
openvasd_get_vts (openvasd_connector_t *);

openvasd_resp_t
openvasd_start_scan (openvasd_connector_t *, char *);

openvasd_resp_t
openvasd_stop_scan (openvasd_connector_t *);

openvasd_resp_t
openvasd_delete_scan (openvasd_connector_t *);

openvasd_resp_t
openvasd_get_scan_results (openvasd_connector_t *, long, long);

openvasd_result_t
openvasd_result_new (unsigned long, gchar *, gchar *, gchar *, gchar *, int,
                     gchar *, gchar *, gchar *, gchar *, gchar *, gchar *,
                     gchar *);

void
openvasd_result_free (openvasd_result_t *);

gchar *openvasd_get_result_member_str (openvasd_result_t,
                                       openvasd_result_member_string_t);

int openvasd_get_result_member_int (openvasd_result_t,
                                    openvasd_result_member_int_t);

int
openvasd_parsed_results (openvasd_connector_t *, unsigned long, unsigned long,
                         GSList **);

openvasd_resp_t
openvasd_get_scan_status (openvasd_connector_t *);

openvasd_scan_status_t
openvasd_parsed_scan_status (openvasd_connector_t *);

int
openvasd_get_scan_progress (openvasd_connector_t *);

openvasd_resp_t
openvasd_get_health_alive (openvasd_connector_t *);
openvasd_resp_t
openvasd_get_health_ready (openvasd_connector_t *);
openvasd_resp_t
openvasd_get_health_started (openvasd_connector_t *);

/* Target builder */

typedef struct openvasd_target openvasd_target_t;

typedef struct openvasd_vt_single openvasd_vt_single_t;

typedef struct openvasd_credential openvasd_credential_t;

typedef struct openvasd_param openvasd_param_t;

openvasd_target_t *
openvasd_target_new (const char *, const char *, const char *, const char *,
                     int, int);

void
openvasd_target_set_finished_hosts (openvasd_target_t *, const char *);

void
openvasd_target_add_alive_test_methods (openvasd_target_t *, gboolean, gboolean,
                                        gboolean, gboolean, gboolean);

void
openvasd_target_free (openvasd_target_t *);

openvasd_param_t *
openvasd_param_new (void);

void
openvasd_param_free (openvasd_param_t *);

openvasd_credential_t *
openvasd_credential_new (const char *, const char *, const char *);

void
openvasd_credential_set_auth_data (openvasd_credential_t *, const char *,
                                   const char *);
void
openvasd_credential_free (openvasd_credential_t *);

void
openvasd_target_add_credential (openvasd_target_t *, openvasd_credential_t *);

openvasd_vt_single_t *
openvasd_vt_single_new (const char *);

void
openvasd_vt_single_free (openvasd_vt_single_t *);
void

openvasd_vt_single_add_value (openvasd_vt_single_t *, const char *,
                              const char *);

/* Scan config builder */
gchar *
openvasd_build_scan_config_json (openvasd_target_t *, GHashTable *, GSList *);

#endif
