/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file security_intelligence.c
 * @brief Security Intelligence client implementation skeleton.
 */

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "libgvm security-intelligence"

#include "security_intelligence.h"

#include <glib.h>
#include <string.h>

/**
 * @brief Connector data for the Security Intelligence service.
 */
struct security_intelligence_connector
{
  gchar *ca_cert;      /**< Path to CA certificate directory/file */
  gchar *cert;         /**< Optional client certificate path */
  gchar *key;          /**< Optional client private key path */
  gchar *bearer_token; /**< OIDC bearer token */
  gchar *host;         /**< Server hostname or IP */
  gint port;           /**< Server port */
  gchar *protocol;     /**< "http" or "https" */
  gchar *url;          /**< Base URL in the form protocol://host:port */
};

/**
 * @brief Creates a new Security Intelligence connector.
 *
 * @return Newly allocated connector on success, NULL on failure.
 */
security_intelligence_connector_t
security_intelligence_connector_new (void)
{
  return g_malloc0 (sizeof (struct security_intelligence_connector));
}

/**
 * @brief Frees a Security Intelligence connector.
 *
 * @param[in] conn Connector to free.
 */
void
security_intelligence_connector_free (security_intelligence_connector_t conn)
{
  if (!conn)
    return;

  g_free (conn->ca_cert);
  g_free (conn->cert);
  g_free (conn->key);
  g_free (conn->bearer_token);
  g_free (conn->host);
  g_free (conn->protocol);
  g_free (conn->url);

  g_free (conn);
}

/**
 * @brief Configures a connector option.
 *
 * @param[in] conn Connector to configure.
 * @param[in] opt Connector option.
 * @param[in] val Value for the option.
 *
 * @return SECURITY_INTELLIGENCE_OK on success, error code otherwise.
 */
security_intelligence_error_t
security_intelligence_connector_builder (
  security_intelligence_connector_t conn,
  security_intelligence_connector_opts_t opt, const void *val)
{
  if (!conn || !val)
    return SECURITY_INTELLIGENCE_INVALID_VALUE;

  switch (opt)
    {
    case SECURITY_INTELLIGENCE_CA_CERT:
      g_free (conn->ca_cert);
      conn->ca_cert = g_strdup ((const gchar *) val);
      break;

    case SECURITY_INTELLIGENCE_CERT:
      g_free (conn->cert);
      conn->cert = g_strdup ((const gchar *) val);
      break;

    case SECURITY_INTELLIGENCE_KEY:
      g_free (conn->key);
      conn->key = g_strdup ((const gchar *) val);
      break;

    case SECURITY_INTELLIGENCE_BEARER_TOKEN:
      g_free (conn->bearer_token);
      conn->bearer_token = g_strdup ((const gchar *) val);
      break;

    case SECURITY_INTELLIGENCE_PROTOCOL:
      if (g_strcmp0 ((const gchar *) val, "http") != 0
          && g_strcmp0 ((const gchar *) val, "https") != 0)
        return SECURITY_INTELLIGENCE_INVALID_VALUE;

      g_free (conn->protocol);
      conn->protocol = g_strdup ((const gchar *) val);
      break;

    case SECURITY_INTELLIGENCE_HOST:
      g_free (conn->host);
      conn->host = g_strdup ((const gchar *) val);
      break;

    case SECURITY_INTELLIGENCE_PORT:
      conn->port = *((const int *) val);
      break;

    case SECURITY_INTELLIGENCE_URL:
      g_free (conn->url);
      conn->url = g_strdup ((const gchar *) val);
      break;

    default:
      return SECURITY_INTELLIGENCE_INVALID_OPT;
    }

  return SECURITY_INTELLIGENCE_OK;
}

/**
 * @brief Allocates a new managed appliance object.
 *
 * @return Newly allocated managed appliance.
 */
security_intelligence_managed_appliance_t
security_intelligence_managed_appliance_new (void)
{
  return g_malloc0 (sizeof (struct security_intelligence_managed_appliance));
}

/**
 * @brief Frees a managed appliance object.
 *
 * @param[in] appliance Managed appliance to free.
 */
void
security_intelligence_managed_appliance_free (
  security_intelligence_managed_appliance_t appliance)
{
  if (!appliance)
    return;

  g_free (appliance->appliance_id);
  g_free (appliance->ip);
  g_free (appliance->gsf_key);
  g_free (appliance->https_certificate_fingerprint);

  g_free (appliance);
}

/**
 * @brief Allocates a new managed report object.
 *
 * @return Newly allocated managed report.
 */
security_intelligence_managed_report_t
security_intelligence_managed_report_new (void)
{
  return g_malloc0 (sizeof (struct security_intelligence_managed_report));
}

/**
 * @brief Frees a managed report object.
 *
 * @param[in] report Managed report to free.
 */
void
security_intelligence_managed_report_free (
  security_intelligence_managed_report_t report)
{
  if (!report)
    return;

  g_free (report->ref_id);

  g_free (report);
}

/**
 * @brief Allocates a managed report list.
 *
 * @param[in] count Number of report slots.
 *
 * @return Newly allocated report list, or NULL on invalid input.
 */
security_intelligence_managed_report_list_t
security_intelligence_managed_report_list_new (int count)
{
  if (count < 0)
    return NULL;

  security_intelligence_managed_report_list_t list =
    g_malloc0 (sizeof (struct security_intelligence_managed_report_list));

  list->count = count;
  list->reports =
    g_malloc0 (sizeof (security_intelligence_managed_report_t) * (count + 1));

  return list;
}

/**
 * @brief Frees a managed report list.
 *
 * @param[in] list Report list to free.
 */
void
security_intelligence_managed_report_list_free (
  security_intelligence_managed_report_list_t list)
{
  if (!list)
    return;

  if (list->reports)
    {
      for (int i = 0; i < list->count; ++i)
        security_intelligence_managed_report_free (list->reports[i]);

      g_free (list->reports);
    }

  g_free (list);
}

/**
 * @brief Allocates a new managed report page object.
 *
 * @return Newly allocated managed report page.
 */
security_intelligence_managed_report_page_t
security_intelligence_managed_report_page_new (void)
{
  return g_malloc0 (sizeof (struct security_intelligence_managed_report_page));
}

/**
 * @brief Frees a managed report page object.
 *
 * @param[in] page Managed report page to free.
 */
void
security_intelligence_managed_report_page_free (
  security_intelligence_managed_report_page_t page)
{
  if (!page)
    return;

  g_free (page);
}

/**
 * @brief Allocates a managed report page list.
 *
 * @param[in] count Number of page slots.
 *
 * @return Newly allocated page list, or NULL on invalid input.
 */
security_intelligence_managed_report_page_list_t
security_intelligence_managed_report_page_list_new (int count)
{
  if (count < 0)
    return NULL;

  security_intelligence_managed_report_page_list_t list =
    g_malloc0 (sizeof (struct security_intelligence_managed_report_page_list));

  list->count = count;
  list->pages = g_malloc0 (sizeof (security_intelligence_managed_report_page_t)
                           * (count + 1));

  return list;
}

/**
 * @brief Frees a managed report page list.
 *
 * @param[in] list Page list to free.
 */
void
security_intelligence_managed_report_page_list_free (
  security_intelligence_managed_report_page_list_t list)
{
  if (!list)
    return;

  if (list->pages)
    {
      for (int i = 0; i < list->count; ++i)
        security_intelligence_managed_report_page_free (list->pages[i]);

      g_free (list->pages);
    }

  g_free (list);
}

/**
 * @brief Converts report upload status enum to wire-format string.
 *
 * @param[in] status Upload status enum.
 *
 * @return Constant string representation.
 */
const gchar *
security_intelligence_report_upload_status_to_string (
  security_intelligence_report_upload_status_t status)
{
  switch (status)
    {
    case SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED:
      return "upload_started";

    case SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED:
      return "upload_completed";

    case SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN:
    default:
      return "unknown";
    }
}

/**
 * @brief Converts wire-format string to report upload status enum.
 *
 * @param[in] status Status string.
 *
 * @return Parsed upload status enum.
 */
security_intelligence_report_upload_status_t
security_intelligence_report_upload_status_from_string (const gchar *status)
{
  if (!status)
    return SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN;

  if (g_strcmp0 (status, "upload_started") == 0)
    return SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED;

  if (g_strcmp0 (status, "upload_completed") == 0)
    return SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED;

  return SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN;
}

/**
 * @brief Builds JSON payload for creating a managed appliance.
 *
 * @param[in] appliance Managed appliance input.
 *
 * @return Newly allocated JSON payload string, or NULL for now.
 */
gchar *
security_intelligence_build_create_managed_appliance_payload (
  security_intelligence_managed_appliance_t appliance)
{
  (void) appliance;

  /* TODO: Build JSON payload */
  return NULL;
}

/**
 * @brief Builds JSON payload for creating a report.
 *
 * @param[in] ref_id Reference ID.
 *
 * @return Newly allocated JSON payload string, or NULL for now.
 */
gchar *
security_intelligence_build_create_report_payload (const gchar *ref_id)
{
  (void) ref_id;

  /* TODO: Build JSON payload */
  return NULL;
}

/**
 * @brief Builds JSON payload for updating report upload status.
 *
 * @param[in] status Upload status.
 *
 * @return Newly allocated JSON payload string, or NULL for now.
 */
gchar *
security_intelligence_build_update_report_status_payload (
  security_intelligence_report_upload_status_t status)
{
  (void) status;

  /* TODO: Build JSON payload */
  return NULL;
}

/**
 * @brief Creates a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] appliance Managed appliance input.
 * @param[out] created Created appliance output.
 * @param[out] errors Optional list of error strings.
 *
 * @return SECURITY_INTELLIGENCE_RESP_OK on success,
 *         SECURITY_INTELLIGENCE_RESP_ERR on failure.
 */
int
security_intelligence_create_managed_appliance (
  security_intelligence_connector_t conn,
  security_intelligence_managed_appliance_t appliance,
  security_intelligence_managed_appliance_t *created, GPtrArray **errors)
{
  (void) conn;
  (void) appliance;
  (void) errors;

  if (created)
    *created = NULL;

  /* TODO: Implement PUT /api/asset-management/managed-appliances/{applianceId}
   */
  return SECURITY_INTELLIGENCE_RESP_ERR;
}

/**
 * @brief Deletes a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] appliance_id OIDC provider client id.
 * @param[out] errors Optional list of error strings.
 *
 * @return SECURITY_INTELLIGENCE_RESP_OK on success,
 *         SECURITY_INTELLIGENCE_RESP_ERR on failure.
 */
int
security_intelligence_delete_managed_appliance (
  security_intelligence_connector_t conn, const gchar *appliance_id,
  GPtrArray **errors)
{
  (void) conn;
  (void) appliance_id;
  (void) errors;

  /* TODO: Implement DELETE
   * /api/asset-management/managed-appliances/{applianceId} */
  return SECURITY_INTELLIGENCE_RESP_ERR;
}

/**
 * @brief Lists reports for a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] appliance_id Appliance UUID string.
 *
 * @return Newly allocated report list on success, NULL on failure.
 */
security_intelligence_managed_report_list_t
security_intelligence_list_reports (security_intelligence_connector_t conn,
                                    const gchar *appliance_id)
{
  (void) conn;
  (void) appliance_id;

  /* TODO: Implement GET /api/asset-management/managed-appliances/reports */
  return NULL;
}

/**
 * @brief Gets a report for a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] appliance_id Appliance UUID string.
 * @param[in] report_id Report UUID string.
 *
 * @return Newly allocated report object on success, NULL on failure.
 */
security_intelligence_managed_report_t
security_intelligence_get_report (security_intelligence_connector_t conn,
                                  const gchar *appliance_id,
                                  const gchar *report_id)
{
  (void) conn;
  (void) appliance_id;
  (void) report_id;

  /* TODO: Implement GET
   * /api/asset-management/managed-appliances/reports/{reportId} */
  return NULL;
}

/**
 * @brief Creates a report for a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] report_id Reference UUID string (Report UUID).
 * @param[out] created Created report output.
 * @param[out] errors Optional list of error strings.
 *
 * @return SECURITY_INTELLIGENCE_RESP_OK on success,
 *         SECURITY_INTELLIGENCE_RESP_ERR on failure.
 */
int
security_intelligence_create_report (
  security_intelligence_connector_t conn, const gchar *report_id,
  security_intelligence_managed_report_t *created, GPtrArray **errors)
{
  (void) conn;
  (void) report_id;
  (void) errors;

  if (created)
    *created = NULL;

  /* TODO: Implement POST /api/asset-management/managed-appliances/reports */
  return SECURITY_INTELLIGENCE_RESP_ERR;
}

/**
 * @brief Adds a report page.
 *
 * @param[in] conn Connector.
 * @param[in] report_id Report UUID string.
 * @param[in] index Page index.
 * @param[in] xml XML payload bytes.
 * @param[in] xml_len XML payload length.
 * @param[out] errors Optional list of error strings.
 *
 * @return SECURITY_INTELLIGENCE_RESP_OK on success,
 *         SECURITY_INTELLIGENCE_RESP_ERR on failure.
 */
int
security_intelligence_add_report_page (security_intelligence_connector_t conn,
                                       const gchar *report_id, int index,
                                       const guint8 *xml, gsize xml_len,
                                       GPtrArray **errors)
{
  (void) conn;
  (void) report_id;
  (void) index;
  (void) xml;
  (void) xml_len;
  (void) errors;

  /* TODO: Implement POST
   * /api/asset-management/managed-appliances/reports/{reportId}/pages/{index}
   */
  return SECURITY_INTELLIGENCE_RESP_ERR;
}

/**
 * @brief Updates report upload status.
 *
 * @param[in] conn Connector.
 * @param[in] report_id Report UUID string.
 * @param[in] status Upload status.
 * @param[out] errors Optional list of error strings.
 *
 * @return SECURITY_INTELLIGENCE_RESP_OK on success,
 *         SECURITY_INTELLIGENCE_RESP_ERR on failure.
 */
int
security_intelligence_update_report_status (
  security_intelligence_connector_t conn, const gchar *report_id,
  security_intelligence_report_upload_status_t status, GPtrArray **errors)
{
  (void) conn;
  (void) report_id;
  (void) status;
  (void) errors;

  /* TODO: Implement PUT
   * /api/asset-management/managed-appliances/reports/{reportId} */
  return SECURITY_INTELLIGENCE_RESP_ERR;
}

/**
 * @brief Gets report pages for a report.
 *
 * @param[in] conn Connector.
 * @param[in] report_id Report UUID string.
 *
 * @return Newly allocated page list on success, NULL on failure.
 */
security_intelligence_managed_report_page_list_t
security_intelligence_get_report_pages (security_intelligence_connector_t conn,
                                        const gchar *report_id)
{
  (void) conn;
  (void) report_id;

  /* TODO: Implement GET
   * /api/asset-management/managed-appliances/reports/{reportId}/pages */
  return NULL;
}