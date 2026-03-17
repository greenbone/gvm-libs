/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file security_intelligence.h
 * @brief Security Intelligence client API for managed appliances and reports.
 *
 * This module provides a high-level API for interacting with the
 * Security Intelligence REST service. It supports:
 *
 * - Creating and deleting managed appliances
 * - Listing and reading managed reports
 * - Creating reports and updating report upload status
 * - Uploading XML report pages
 * - Reading report pages
 *
 * Core data structures:
 * - `security_intelligence_connector_t`
 * - `security_intelligence_managed_appliance_t`
 * - `security_intelligence_managed_report_t`
 * - `security_intelligence_managed_report_page_t`
 */

#ifndef _GVM_SECURITY_INTELLIGENCE_SECURITY_INTELLIGENCE_H
#define _GVM_SECURITY_INTELLIGENCE_SECURITY_INTELLIGENCE_H

#include <glib.h>
#include <stddef.h>

#define SECURITY_INTELLIGENCE_RESP_ERR -1
#define SECURITY_INTELLIGENCE_RESP_OK 0

/**
 * @brief Connector builder options.
 */
typedef enum
{
  SECURITY_INTELLIGENCE_CA_CERT,
  SECURITY_INTELLIGENCE_CERT,
  SECURITY_INTELLIGENCE_KEY,
  SECURITY_INTELLIGENCE_BEARER_TOKEN,
  SECURITY_INTELLIGENCE_PROTOCOL,
  SECURITY_INTELLIGENCE_HOST,
  SECURITY_INTELLIGENCE_PORT,
  SECURITY_INTELLIGENCE_URL,
} security_intelligence_connector_opts_t;

/**
 * @brief Error codes for connector configuration.
 */
typedef enum
{
  SECURITY_INTELLIGENCE_OK = 0,
  SECURITY_INTELLIGENCE_INVALID_OPT = -1,
  SECURITY_INTELLIGENCE_INVALID_VALUE = -2
} security_intelligence_error_t;

/**
 * @brief Report upload status.
 */
typedef enum
{
  SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN = 0,
  SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
  SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED
} security_intelligence_report_upload_status_t;

/**
 * @brief Opaque connector type.
 */
typedef struct security_intelligence_connector
  *security_intelligence_connector_t;

/**
 * @brief Managed appliance object.
 */
struct security_intelligence_managed_appliance
{
  gchar *appliance_id; ///< OIDC provider client id
  gchar *ip;           ///< IP address
  gchar *gsf_key;      ///< GSF key e.g: gsf<number>@feed.greenbone.net
  gchar *https_certificate_fingerprint; ///< TLS certificate fingerprint
};
typedef struct security_intelligence_managed_appliance
  *security_intelligence_managed_appliance_t;

/**
 * @brief Managed report object.
 */
struct security_intelligence_managed_report
{
  gchar *ref_id; ///< Report UUID/reference UUID
  security_intelligence_report_upload_status_t upload_status;
};
typedef struct security_intelligence_managed_report
  *security_intelligence_managed_report_t;

/**
 * @brief Managed report list.
 */
struct security_intelligence_managed_report_list
{
  int count;
  security_intelligence_managed_report_t *reports;
};
typedef struct security_intelligence_managed_report_list
  *security_intelligence_managed_report_list_t;

/**
 * @brief Managed report page object.
 */
struct security_intelligence_managed_report_page
{
  int index; ///< Page index
};
typedef struct security_intelligence_managed_report_page
  *security_intelligence_managed_report_page_t;

/**
 * @brief Managed report page list.
 */
struct security_intelligence_managed_report_page_list
{
  int count;
  security_intelligence_managed_report_page_t *pages;
};
typedef struct security_intelligence_managed_report_page_list
  *security_intelligence_managed_report_page_list_t;

/* connector */

security_intelligence_connector_t
security_intelligence_connector_new (void);

security_intelligence_error_t
security_intelligence_connector_builder (
  security_intelligence_connector_t conn,
  security_intelligence_connector_opts_t opt, const void *val);

void
security_intelligence_connector_free (security_intelligence_connector_t conn);

/* managed appliance objects */

security_intelligence_managed_appliance_t
security_intelligence_managed_appliance_new (void);

void
security_intelligence_managed_appliance_free (
  security_intelligence_managed_appliance_t appliance);

/* managed report objects */

security_intelligence_managed_report_t
security_intelligence_managed_report_new (void);

void
security_intelligence_managed_report_free (
  security_intelligence_managed_report_t report);

security_intelligence_managed_report_list_t
security_intelligence_managed_report_list_new (int count);

void
security_intelligence_managed_report_list_free (
  security_intelligence_managed_report_list_t list);

security_intelligence_managed_report_page_t
security_intelligence_managed_report_page_new (void);

void
security_intelligence_managed_report_page_free (
  security_intelligence_managed_report_page_t page);

security_intelligence_managed_report_page_list_t
security_intelligence_managed_report_page_list_new (int count);

void
security_intelligence_managed_report_page_list_free (
  security_intelligence_managed_report_page_list_t list);

/* enum/string helpers */

const gchar *
security_intelligence_report_upload_status_to_string (
  security_intelligence_report_upload_status_t status);

security_intelligence_report_upload_status_t
security_intelligence_report_upload_status_from_string (const gchar *status);

/* serialization helpers */

gchar *
security_intelligence_build_create_managed_appliance_payload (
  security_intelligence_managed_appliance_t appliance);

gchar *
security_intelligence_build_create_report_payload (const gchar *ref_id);

gchar *
security_intelligence_build_update_report_status_payload (
  security_intelligence_report_upload_status_t status);

/* REST operations */

int
security_intelligence_create_managed_appliance (
  security_intelligence_connector_t conn,
  security_intelligence_managed_appliance_t appliance,
  security_intelligence_managed_appliance_t *created, GPtrArray **errors);

int
security_intelligence_delete_managed_appliance (
  security_intelligence_connector_t conn, const gchar *appliance_id,
  GPtrArray **errors);

security_intelligence_managed_report_list_t
security_intelligence_list_reports (security_intelligence_connector_t conn,
                                    const gchar *appliance_id);

security_intelligence_managed_report_t
security_intelligence_get_report (security_intelligence_connector_t conn,
                                  const gchar *appliance_id,
                                  const gchar *report_id);

int
security_intelligence_create_report (
  security_intelligence_connector_t conn, const gchar *report_id,
  security_intelligence_managed_report_t *created, GPtrArray **errors);

int
security_intelligence_add_report_page (security_intelligence_connector_t conn,
                                       const gchar *report_id, int index,
                                       const guint8 *xml, gsize xml_len,
                                       GPtrArray **errors);

int
security_intelligence_update_report_status (
  security_intelligence_connector_t conn, const gchar *report_id,
  security_intelligence_report_upload_status_t status, GPtrArray **errors);

security_intelligence_managed_report_page_list_t
security_intelligence_get_report_pages (security_intelligence_connector_t conn,
                                        const gchar *report_id);

#endif /* _GVM_SECURITY_INTELLIGENCE_SECURITY_INTELLIGENCE_H */