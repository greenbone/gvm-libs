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

#include "../http/httputils.h"
#include "../util/json.h"

#include <cjson/cJSON.h>

static const gchar *CONTENT_TYPE_JSON = "application/json";
static const gchar *CONTENT_TYPE_XML = "application/xml";

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
 * @brief Initialize custom HTTP headers for Security Intelligence requests.
 *
 * @param[in] token The JWT to use for Authorization.
 * @param[in] content_type Value to add "Content-Type: application/json"
 *
 * @return A newly allocated `gvm_http_headers_t *` containing the headers.
 *         Must be freed with `gvm_http_headers_free()`.
 */
static gvm_http_headers_t *
init_custom_header (const gchar *token, const gchar *content_type)
{
  gvm_http_headers_t *headers = gvm_http_headers_new ();

  // Set Bearer token
  if (token)
    {
      GString *auth = g_string_new ("Authorization: Bearer ");
      g_string_append (auth, token);

      if (!gvm_http_add_header (headers, auth->str))
        g_warning ("%s: Not possible to set Authorization header", __func__);

      g_string_free (auth, TRUE);
    }

  // Set Content-Type: application/json or application/xml
  if (content_type != NULL)
    {
      GString *content = g_string_new ("Content-Type: ");
      g_string_append (content, content_type);
      if (!gvm_http_add_header (headers, content->str))
        g_warning ("%s: Failed to set Content-Type header", __func__);

      g_string_free (content, TRUE);
    }

  return headers;
}

/**
 * @brief Sends an HTTP(S) request to the security-intelligence server.
 *
 * @param[in] conn          The `security_intelligence_connector_t` containing
 *                          server and certificate details.
 * @param[in] method        The HTTP method (GET, POST, PUT, etc.).
 * @param[in] path          The request path (e.g., "/api/asset-management").
 * @param[in] payload       Optional request body payload.
 * @param[in] content_type  Content type for header.
 *
 * @return Pointer to a `gvm_http_response_t` containing status code and body.
 *         Must be freed using `gvm_http_response_free()`.
 */
static gvm_http_response_t *
security_intelligence_send_request (security_intelligence_connector_t conn,
                                    gvm_http_method_t method, const gchar *path,
                                    const gchar *payload,
                                    const gchar *content_type)
{
  gchar *url = NULL;
  if (!conn)
    {
      g_warning ("%s: Missing connection", __func__);
      return NULL;
    }

  if (!conn->protocol || !conn->host)
    {
      g_warning ("%s: Missing URL components", __func__);
      return NULL;
    }

  if (conn->url)
    url = g_strdup_printf ("%s%s", conn->url, path);
  else
    url = g_strdup_printf ("%s://%s:%d%s", conn->protocol, conn->host,
                           conn->port, path);

  gvm_http_headers_t *headers =
    init_custom_header (conn->bearer_token, content_type);

  gvm_http_response_t *http_response = gvm_http_request (
    url, method, payload, headers, conn->ca_cert, conn->cert, conn->key,
    NULL // No manual stream allocation
  );

  g_free (url);
  gvm_http_headers_free (headers);

  if (!http_response)
    {
      g_warning ("%s: HTTP request failed", __func__);
      return NULL;
    }

  return http_response;
}

/**
 * @brief Ensure an error array exists and uses g_free on elements.
 *
 * @param[in,out] errors GPtrArray for initialization.
 */
static void
ensure_error_array (GPtrArray **errors)
{
  if (errors && *errors == NULL)
    *errors = g_ptr_array_new_with_free_func (g_free);
}

/**
 * @brief Add a single error message to errors, creating the array if needed.
 *
 * @param[in,out] errors Array to add error message to.
 * @param[in] msg Error message.
 */
static void
push_error (GPtrArray **errors, const gchar *msg)
{
  if (!errors || !msg || !*msg)
    return;

  ensure_error_array (errors);
  g_ptr_array_add (*errors, g_strdup (msg));
}

/**
 * @brief Add a formatted error message to errors.
 *
 * @param[in,out] errors Array to add error message to.
 * @param[in] format printf-style format string.
 */
static void
push_error_printf (GPtrArray **errors, const gchar *format, ...)
{
  va_list args;
  gchar *msg;

  if (!errors || !format || !*format)
    return;

  va_start (args, format);
  msg = g_strdup_vprintf (format, args);
  va_end (args);

  if (msg && *msg)
    push_error (errors, msg);

  g_free (msg);
}

/**
 * @brief Return a fallback label for a missing/empty field key.
 *
 * @param[in] key Field key from JSON object.
 *
 * @return key if non-empty, otherwise "unknown".
 */
static const gchar *
error_field_or_unknown (const gchar *key)
{
  return (key && *key) ? key : "unknown";
}

/**
 * @brief Parse ErrorResponse JSON body into a flat string array.
 *
 * Expected format:
 * {
 *   "type": "...",
 *   "title": "...",
 *   "details": "...",
 *   "errors": {
 *     "field": "message"
 *   }
 * }
 *
 * Output format in errors array:
 * - title
 * - details
 * - field-specific messages as "field: message"
 *
 * @param[in] body Response body (must be NUL-terminated JSON text).
 * @param[in] http_status HTTP status code for fallback/context messages.
 * @param[out] errors Parsed errors.
 */
static void
parse_error_response_json_into_array (const gchar *body, int http_status,
                                      GPtrArray **errors)
{
  cJSON *root;
  cJSON *title;
  cJSON *details;
  cJSON *type;
  cJSON *errors_obj;
  gboolean any_added = FALSE;

  if (!errors)
    return;

  if (!body || !*body)
    {
      push_error_printf (errors, "Request failed (%d).", http_status);
      return;
    }

  root = cJSON_Parse (body);
  if (!root)
    {
      push_error_printf (errors,
                         "Request failed (%d): invalid JSON error response.",
                         http_status);
      return;
    }

  type = cJSON_GetObjectItem (root, "type");
  title = cJSON_GetObjectItem (root, "title");
  details = cJSON_GetObjectItem (root, "details");
  errors_obj = cJSON_GetObjectItem (root, "errors");

  if (cJSON_IsString (title) && title->valuestring && *title->valuestring)
    {
      push_error (errors, title->valuestring);
      any_added = TRUE;
    }

  if (cJSON_IsString (details) && details->valuestring && *details->valuestring)
    {
      push_error (errors, details->valuestring);
      any_added = TRUE;
    }

  if (cJSON_IsObject (errors_obj))
    {
      const cJSON *entry = NULL;

      cJSON_ArrayForEach (entry, errors_obj)
      {
        const gchar *field = error_field_or_unknown (entry->string);

        if (cJSON_IsString (entry) && entry->valuestring && *entry->valuestring)
          {
            push_error_printf (errors, "%s: %s", field, entry->valuestring);
            any_added = TRUE;
          }
        else if (cJSON_IsArray (entry))
          {
            /* Defensive support in case a field ever becomes []string. */
            int n = cJSON_GetArraySize (entry);
            for (int i = 0; i < n; ++i)
              {
                const cJSON *item = cJSON_GetArrayItem (entry, i);
                if (cJSON_IsString (item) && item->valuestring
                    && *item->valuestring)
                  {
                    push_error_printf (errors, "%s: %s", field,
                                       item->valuestring);
                    any_added = TRUE;
                  }
              }
          }
        else if (cJSON_IsObject (entry))
          {
            /* Defensive support for nested objects. */
            gchar *printed = cJSON_PrintUnformatted ((cJSON *) entry);
            if (printed && *printed)
              {
                push_error_printf (errors, "%s: %s", field, printed);
                any_added = TRUE;
              }
            cJSON_free (printed);
          }
      }
    }

  if (!any_added)
    {
      if (cJSON_IsString (type) && type->valuestring && *type->valuestring)
        push_error_printf (errors, "Request failed (%d): %s", http_status,
                           type->valuestring);
      else
        push_error_printf (
          errors, "Request failed (%d), but no detailed error was provided.",
          http_status);
    }

  cJSON_Delete (root);
}

/**
 * @brief Parses managed appliance JSON object.
 *
 * @param[in] item The cJSON object representing one managed appliance.
 * @param[out] appliance Parsed appliance output.
 *
 * @return Parsed appliance on success, NULL on failure.
 */
static security_intelligence_managed_appliance_t
security_intelligence_parse_managed_appliance (
  cJSON *item, security_intelligence_managed_appliance_t *appliance)
{
  const gchar *appliance_id;
  const gchar *ip;
  const gchar *fingerprint;

  if (!appliance)
    return NULL;

  *appliance = NULL;

  if (!item || !cJSON_IsObject (item))
    return NULL;

  appliance_id = gvm_json_obj_str (item, "applianceId");
  ip = gvm_json_obj_str (item, "ip");
  fingerprint = gvm_json_obj_str (item, "httpsCertificateFingerprint");

  if (!appliance_id || !*appliance_id)
    return NULL;

  if (!ip || !*ip)
    return NULL;

  if (!fingerprint || !*fingerprint)
    return NULL;

  *appliance = security_intelligence_managed_appliance_new ();
  if (!*appliance)
    return NULL;

  (*appliance)->appliance_id = g_strdup (appliance_id);
  (*appliance)->ip = g_strdup (ip);
  (*appliance)->https_certificate_fingerprint = g_strdup (fingerprint);

  if (!(*appliance)->appliance_id || !(*appliance)->ip
      || !(*appliance)->https_certificate_fingerprint)
    {
      security_intelligence_managed_appliance_free (*appliance);
      *appliance = NULL;
      return NULL;
    }

  return *appliance;
}

/**
 * @brief Parse a managed report JSON object.
 *
 * @param[in] item cJSON object representing a managed report.
 *
 * @return Newly allocated managed report on success, NULL on failure.
 */
static security_intelligence_managed_report_t
security_intelligence_parse_managed_report (cJSON *item)
{
  security_intelligence_managed_report_t report;
  const gchar *status;
  const gchar *ref_id;

  if (!item || !cJSON_IsObject (item))
    return NULL;

  ref_id = gvm_json_obj_str (item, "refId");
  if (!ref_id || !*ref_id)
    return NULL;

  status = gvm_json_obj_str (item, "uploadStatus");

  report = security_intelligence_managed_report_new ();

  report->ref_id = g_strdup (ref_id);
  if (!report->ref_id)
    {
      security_intelligence_managed_report_free (report);
      return NULL;
    }

  report->upload_status =
    security_intelligence_report_upload_status_from_string (status);

  return report;
}

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
 * @return Newly allocated JSON payload string on success, NULL on failure.
 *         The caller owns the returned string and must free it with
 *         cJSON_free().
 */
gchar *
security_intelligence_build_create_managed_appliance_payload (
  security_intelligence_managed_appliance_t appliance)
{
  cJSON *root;
  gchar *payload;

  if (!appliance)
    return NULL;

  if (!appliance->ip || !*appliance->ip)
    return NULL;

  if (!appliance->https_certificate_fingerprint
      || !*appliance->https_certificate_fingerprint)
    return NULL;

  root = cJSON_CreateObject ();
  if (!root)
    return NULL;

  cJSON_AddStringToObject (root, "ip", appliance->ip);

  cJSON_AddStringToObject (root, "httpsCertificateFingerprint",
                           appliance->https_certificate_fingerprint);

  payload = cJSON_PrintUnformatted (root);
  cJSON_Delete (root);

  return payload;
}

/**
 * @brief Builds JSON payload for creating a report.
 *
 * @param[in] ref_id Reference ID (Report UUID).
 *
 * @return Newly allocated JSON payload string on success, NULL on failure.
 *         The caller owns the returned string and must free it with
 *         cJSON_free().
 */
gchar *
security_intelligence_build_create_report_payload (const gchar *ref_id)
{
  cJSON *root;
  gchar *payload;
  if (!ref_id || !*ref_id)
    return NULL;

  root = cJSON_CreateObject ();
  if (!root)
    return NULL;
  cJSON_AddStringToObject (root, "refId", ref_id);

  payload = cJSON_PrintUnformatted (root);
  cJSON_Delete (root);

  return payload;
}

/**
 * @brief Builds JSON payload for updating report upload status.
 *
 * @param[in] status Upload status.
 *
 * @return Newly allocated JSON payload string on success, NULL on failure.
 *         The caller owns the returned string and must free it with
 *         cJSON_free().
 */
gchar *
security_intelligence_build_update_report_status_payload (
  security_intelligence_report_upload_status_t status)
{
  cJSON *root;
  gchar *payload;
  if (status == SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN)
    return NULL;

  root = cJSON_CreateObject ();
  if (!root)
    return NULL;

  const char *status_str =
    security_intelligence_report_upload_status_to_string (status);
  cJSON_AddStringToObject (root, "status", status_str);

  payload = cJSON_PrintUnformatted (root);
  cJSON_Delete (root);

  return payload;
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
  gchar *payload = NULL;
  gchar *path = NULL;
  cJSON *root = NULL;
  gvm_http_response_t *response = NULL;

  if (created)
    *created = NULL;

  if (!conn || !appliance || !created)
    {
      g_warning ("%s: Invalid connection or appliance", __func__);
      push_error (errors, "Invalid connection or appliance.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (!appliance->appliance_id || !*appliance->appliance_id)
    {
      g_warning ("%s: Invalid appliance id", __func__);
      push_error (errors, "Invalid appliance id.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  payload =
    security_intelligence_build_create_managed_appliance_payload (appliance);
  if (!payload)
    {
      g_warning ("%s: Failed to build managed appliance payload", __func__);
      push_error (errors, "Failed to build managed appliance payload.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  path = g_strdup_printf ("/api/asset-management/managed-appliances/%s",
                          appliance->appliance_id);

  response = security_intelligence_send_request (conn, PUT, path, payload,
                                                 CONTENT_TYPE_JSON);

  g_free (path);
  cJSON_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      push_error (errors, "Failed to get response.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      parse_error_response_json_into_array (response->data,
                                            response->http_status, errors);
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  root = cJSON_Parse (response->data);
  if (!root)
    {
      g_warning ("%s: Failed to parse JSON response", __func__);
      push_error (errors, "Failed to parse JSON response.");
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (!security_intelligence_parse_managed_appliance (root, created))
    {
      g_warning ("%s: Failed to parse managed appliance", __func__);
      push_error (errors, "Failed to parse managed appliance response.");
      cJSON_Delete (root);
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  cJSON_Delete (root);
  gvm_http_response_free (response);

  return SECURITY_INTELLIGENCE_RESP_OK;
}

/**
 * @brief Deletes a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] appliance_id OIDC provider client id.
 *
 * @return SECURITY_INTELLIGENCE_RESP_OK on success,
 *         SECURITY_INTELLIGENCE_RESP_ERR on failure.
 */
int
security_intelligence_delete_managed_appliance (
  security_intelligence_connector_t conn, const gchar *appliance_id)
{
  gchar *path = NULL;
  gvm_http_response_t *response = NULL;

  if (!conn || !appliance_id || !*appliance_id)
    return SECURITY_INTELLIGENCE_RESP_ERR;

  path = g_strdup_printf ("/api/asset-management/managed-appliances/%s",
                          appliance_id);

  response = security_intelligence_send_request (conn, DELETE, path, NULL,
                                                 CONTENT_TYPE_JSON);

  g_free (path);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  return SECURITY_INTELLIGENCE_RESP_OK;
}

/**
 * @brief Lists reports for a managed appliance.
 *
 * @param[in] conn Connector.
 *
 * @return Newly allocated report list on success, NULL on failure.
 */
security_intelligence_managed_report_list_t
security_intelligence_list_reports (security_intelligence_connector_t conn)
{
  gvm_http_response_t *response = NULL;
  cJSON *root = NULL;
  security_intelligence_managed_report_list_t reports = NULL;
  int count;
  int valid_index = 0;

  if (!conn)
    return NULL;

  response = security_intelligence_send_request (
    conn, GET, "/api/asset-management/managed-appliances/reports", NULL,
    CONTENT_TYPE_JSON);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return NULL;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      gvm_http_response_free (response);
      return NULL;
    }

  root = cJSON_Parse (response->data);
  if (!root || !cJSON_IsArray (root))
    {
      g_warning ("%s: Failed to parse JSON response", __func__);
      if (root)
        cJSON_Delete (root);
      gvm_http_response_free (response);
      return NULL;
    }

  count = cJSON_GetArraySize (root);
  reports = security_intelligence_managed_report_list_new (count);

  for (int i = 0; i < count; i++)
    {
      cJSON *item = cJSON_GetArrayItem (root, i);
      security_intelligence_managed_report_t report =
        security_intelligence_parse_managed_report (item);

      if (report)
        reports->reports[valid_index++] = report;
    }

  reports->count = valid_index;

  cJSON_Delete (root);
  gvm_http_response_free (response);

  return reports;
}

/**
 * @brief Gets a report for a managed appliance.
 *
 * @param[in] conn Connector.
 * @param[in] report_id Report UUID string.
 * @param[out] errors Optional list of error strings.
 *
 * @return Newly allocated report object on success, NULL on failure.
 */
security_intelligence_managed_report_t
security_intelligence_get_report (security_intelligence_connector_t conn,
                                  const gchar *report_id, GPtrArray **errors)
{
  gchar *path = NULL;
  gvm_http_response_t *response = NULL;
  security_intelligence_managed_report_t report = NULL;
  cJSON *root = NULL;
  if (!conn || !report_id || !*report_id)
    return NULL;

  path = g_strdup_printf ("/api/asset-management/managed-appliances/reports/%s",
                          report_id);

  response = security_intelligence_send_request (conn, GET, path, NULL,
                                                 CONTENT_TYPE_JSON);
  g_free (path);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return NULL;
    }
  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      parse_error_response_json_into_array (response->data,
                                            response->http_status, errors);
      gvm_http_response_free (response);
      return NULL;
    }
  root = cJSON_Parse (response->data);
  if (!root)
    {
      g_warning ("%s: Failed to parse JSON response", __func__);
      push_error (errors, "Failed to parse JSON response.");
      gvm_http_response_free (response);
      return NULL;
    }

  report = security_intelligence_parse_managed_report (root);
  if (!report)
    push_error (errors, "Failed to parse managed report response.");

  cJSON_Delete (root);
  gvm_http_response_free (response);

  return report;
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
  gvm_http_response_t *response = NULL;
  gchar *payload = NULL;
  cJSON *root = NULL;

  if (created)
    *created = NULL;

  if (!conn || !report_id || !*report_id || !created)
    return SECURITY_INTELLIGENCE_RESP_ERR;

  payload = security_intelligence_build_create_report_payload (report_id);
  if (!payload)
    {
      g_warning ("%s: Failed to build payload", __func__);
      push_error (errors, "Failed to build payload.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  response = security_intelligence_send_request (
    conn, POST, "/api/asset-management/managed-appliances/reports", payload,
    CONTENT_TYPE_JSON);

  cJSON_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get JSON response", __func__);
      push_error (errors, "Failed to get JSON response.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_warning ("%s: Received HTTP status %ld", __func__,
                 response->http_status);
      parse_error_response_json_into_array (response->data,
                                            response->http_status, errors);
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  root = cJSON_Parse (response->data);

  if (!root)
    {
      g_warning ("%s: Failed to parse JSON response", __func__);
      push_error (errors, "Failed to parse JSON response.");
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  *created = security_intelligence_parse_managed_report (root);
  if (!*created)
    {
      g_warning ("%s: Failed to parse managed report response.", __func__);
      push_error (errors, "Failed to parse managed report response.");
      gvm_http_response_free (response);
      cJSON_Delete (root);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  cJSON_Delete (root);
  gvm_http_response_free (response);
  return SECURITY_INTELLIGENCE_RESP_OK;
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
  gchar *path = NULL;
  gchar *payload = NULL;
  gvm_http_response_t *response = NULL;

  if (!conn)
    {
      g_warning ("%s: Invalid connector", __func__);
      push_error (errors, "Invalid connector.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (!report_id || !*report_id)
    {
      g_warning ("%s: Invalid report id", __func__);
      push_error (errors, "Invalid report id.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (index < 0)
    {
      g_warning ("%s: Invalid page index", __func__);
      push_error (errors, "Invalid page index.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (!xml || xml_len == 0)
    {
      g_warning ("%s: Missing XML payload", __func__);
      push_error (errors, "Missing XML payload.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  path = g_strdup_printf (
    "/api/asset-management/managed-appliances/reports/%s/pages/%d", report_id,
    index);

  payload = g_strndup ((const gchar *) xml, xml_len);

  response = security_intelligence_send_request (conn, POST, path, payload,
                                                 CONTENT_TYPE_XML);

  g_free (path);
  g_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      push_error (errors, "Failed to get response.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      parse_error_response_json_into_array (response->data,
                                            response->http_status, errors);
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  gvm_http_response_free (response);

  return SECURITY_INTELLIGENCE_RESP_OK;
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
  gchar *path = NULL;
  gchar *payload = NULL;
  gvm_http_response_t *response = NULL;

  if (!conn)
    {
      g_warning ("%s: Invalid connector", __func__);
      push_error (errors, "Invalid connector.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (!report_id || !*report_id)
    {
      g_warning ("%s: Invalid report id", __func__);
      push_error (errors, "Invalid report id.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  path = g_strdup_printf ("/api/asset-management/managed-appliances/reports/%s",
                          report_id);
  payload = security_intelligence_build_update_report_status_payload (status);

  if (!payload)
    {
      g_warning ("%s: Failed to build update report status payload", __func__);
      push_error (errors, "Failed to build update report status payload.");
      g_free (path);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  response = security_intelligence_send_request (conn, PUT, path, payload,
                                                 CONTENT_TYPE_JSON);
  g_free (path);
  g_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      push_error (errors, "Failed to get response.");
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      parse_error_response_json_into_array (response->data,
                                            response->http_status, errors);
      gvm_http_response_free (response);
      return SECURITY_INTELLIGENCE_RESP_ERR;
    }

  gvm_http_response_free (response);

  return SECURITY_INTELLIGENCE_RESP_OK;
}

/**
 * @brief Gets report pages for a report.
 *
 * @param[in] conn Connector.
 * @param[in] report_id Report UUID string.
 * @param[out] errors Optional list of error strings.
 *
 * @return Newly allocated page list on success, NULL on failure.
 */
security_intelligence_managed_report_page_list_t
security_intelligence_get_report_pages (security_intelligence_connector_t conn,
                                        const gchar *report_id,
                                        GPtrArray **errors)
{
  gchar *path = NULL;
  gvm_http_response_t *response = NULL;
  cJSON *root = NULL;
  security_intelligence_managed_report_page_list_t pages = NULL;
  int count;
  int valid_index = 0;

  if (!conn)
    {
      g_warning ("%s: Invalid connector", __func__);
      push_error (errors, "Invalid connector.");
      return NULL;
    }

  if (!report_id || !*report_id)
    {
      g_warning ("%s: Invalid report id", __func__);
      push_error (errors, "Invalid report id.");
      return NULL;
    }

  path = g_strdup_printf (
    "/api/asset-management/managed-appliances/reports/%s/pages", report_id);

  response = security_intelligence_send_request (conn, GET, path, NULL, NULL);
  g_free (path);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      push_error (errors, "Failed to get response.");
      return NULL;
    }

  if (response->http_status < 200 || response->http_status >= 300)
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      parse_error_response_json_into_array (response->data,
                                            response->http_status, errors);
      gvm_http_response_free (response);
      return NULL;
    }

  root = cJSON_Parse (response->data);
  if (!root || !cJSON_IsArray (root))
    {
      g_warning ("%s: Failed to parse response", __func__);
      push_error (errors, "Failed to parse response.");
      if (root)
        cJSON_Delete (root);
      gvm_http_response_free (response);
      return NULL;
    }

  count = cJSON_GetArraySize (root);
  pages = security_intelligence_managed_report_page_list_new (count);

  for (int i = 0; i < count; i++)
    {
      cJSON *page = cJSON_GetArrayItem (root, i);

      if (cJSON_IsObject (page))
        {
          security_intelligence_managed_report_page_t p;
          int index = gvm_json_obj_int (page, "index");

          p = security_intelligence_managed_report_page_new ();
          p->index = index;
          pages->pages[valid_index++] = p;
        }
    }

  pages->count = valid_index;

  cJSON_Delete (root);
  gvm_http_response_free (response);

  return pages;
}