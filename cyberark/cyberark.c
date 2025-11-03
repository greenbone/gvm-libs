/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for communication with CyberArk credential store. (Experimental)
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm cyberark"

#include "cyberark.h"

#include "../http/httputils.h"
#include "../util/json.h"

#include <cjson/cJSON.h>

/**
 * @brief Struct holding the data for connecting with the CyberArk.
 */
struct cyberark_connector
{
  gchar *ca_cert;  /**< CA certificate. */
  gchar *cert;     /**< Client certificate. */
  gchar *key;      /**< Client private key. */
  gchar *apikey;   /**< API key for authentication.(Optional) */
  gchar *host;     /**< Credential store hostname or IP. */
  gchar *path;     /**< Base path of CyberArk API. */
  gint port;       /**< Port number. */
  gchar *protocol; /**< "http" or "https". */
  gchar *app_id;   /**< Application ID. */
};

/**
 * @brief Creates a new CyberArk connector.
 */
cyberark_connector_t
cyberark_connector_new (void)
{
  return g_malloc0 (sizeof (struct cyberark_connector));
}

/**
 * @brief Frees a CyberArk connector.
 *
 * @param[in] connector Connector to be freed
 */
void
cyberark_connector_free (cyberark_connector_t connector)
{
  if (!connector)
    return;

  g_free (connector->ca_cert);
  g_free (connector->cert);
  g_free (connector->key);
  g_free (connector->apikey);
  g_free (connector->host);
  g_free (connector->path);
  g_free (connector->protocol);
  g_free (connector->app_id);

  g_free (connector);
}

/** @brief Build a CyberArk connector.
 *
 *  Receive option name and value to build the connector.
 *
 *  @param conn   connector information.
 *  @param opt    option to set.
 *  @param val    value to set.
 *
 *  @return Return CYBERARK_OK on success, otherwise error.
 */
cyberark_error_t
cyberark_connector_builder (cyberark_connector_t conn,
                            cyberark_connector_opts_t opt,
                            const void *val)
{
  if (conn == NULL || val == NULL)
    return CYBERARK_INVALID_VALUE;

  if (opt < CYBERARK_CA_CERT || opt > CYBERARK_APP_ID)
    return CYBERARK_INVALID_OPT;

  switch (opt)
    {
    case CYBERARK_CA_CERT:
      conn->ca_cert = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_CERT:
      conn->cert = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_KEY:
      conn->key = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_API_KEY:
      conn->apikey = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_PROTOCOL:
      if (g_strcmp0 ((const gchar *) val, "http") != 0
          && g_strcmp0 ((const gchar *) val, "https") != 0)
        return CYBERARK_INVALID_VALUE;
      conn->protocol = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_HOST:
      conn->host = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_PATH:
      conn->path = g_strdup ((const gchar *) val);
      break;
    case CYBERARK_PORT:
      conn->port = *((const int *) val);
      break;
    case CYBERARK_APP_ID:
      conn->app_id = g_strdup ((const gchar *) val);
      break;
    default:
      return CYBERARK_INVALID_OPT;
    }

  return CYBERARK_OK;
}

/**
 * @brief Initialize custom HTTP headers for CyberArk requests.
 *
 * @param[in] apikey The Api Key to use for Authorization (optional).
 * @param[in] content_type Whether to add "Content-Type: application/json"
 * (TRUE/FALSE).
 *
 * @return A newly allocated `gvm_http_headers_t *` containing the headers.
 *         Must be freed with `gvm_http_headers_free()`.
 */
static gvm_http_headers_t *
init_custom_header (const gchar *apikey, gboolean content_type)
{
  gvm_http_headers_t *headers = gvm_http_headers_new ();

  // Set API KEY
  if (apikey)
    {
      GString *xapikey = g_string_new ("X-API-KEY: ");
      g_string_append (xapikey, apikey);

      if (!gvm_http_add_header (headers, xapikey->str))
        g_warning ("%s: Not possible to set API-KEY", __func__);

      g_string_free (xapikey, TRUE);
    }

  // Set Content-Type: application/json
  if (content_type)
    {
      if (!gvm_http_add_header (headers, "Content-Type: application/json"))
        g_warning ("%s: Failed to set Content-Type header", __func__);
    }

  return headers;
}

/**
 * @brief Sends an HTTP(S) request to a CyberArk.
 *
 * @param[in] conn          The connection containing server and certificate details.
 * @param[in] method        The HTTP method (GET, POST, PUT, etc.).
 * @param[in] path          The request path.
 * @param[in] payload       Optional request body payload.
 * @param[in] apikey        Optional Api key for Authorization header.
 *
 * @return Pointer to a `gvm_http_response_t` containing status code and body.
 *         Must be freed using `gvm_http_response_free()`.
 */
static gvm_http_response_t *
cyberark_send_request (cyberark_connector_t conn,
                               gvm_http_method_t method,
                               const gchar *request_path,
                               const gchar *payload,
                               const gchar *apikey)
{
  if (!conn)
    {
      g_warning ("%s: Missing connection", __func__);
      return NULL;
    }

  if (!conn->protocol || !conn->host || !conn->path || !request_path)
    {
      g_warning ("%s: Missing URL components", __func__);
      return NULL;
    }

  gchar *url;

  if (conn->port )
    url =  g_strdup_printf ("%s://%s:%d%s%s", conn->protocol, conn->host,
                            conn->port, conn->path, request_path);
  else
    url =  g_strdup_printf ("%s://%s%s%s", conn->protocol, conn->host,
                            conn->path, request_path);

  gvm_http_headers_t *headers = init_custom_header (apikey, payload ? TRUE : FALSE);

  gvm_http_response_t *http_response = gvm_http_request (
    url, method, payload, headers, conn->ca_cert, conn->cert, conn->key, NULL);

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
 * @brief Create a new CyberArk object.
 *
 * @return A newly allocated `cyberark_object_t`. Must be freed with
 *         `cyberark_object_free()`.
 */
cyberark_object_t
cyberark_object_new (void)
{
  cyberark_object_t obj = g_malloc0 (sizeof (struct cyberark_object));
  return obj;
}

/**
 * @brief Free a CyberArk object.
 *
 * @param obj The CyberArk object to free.
 */
void
cyberark_object_free (cyberark_object_t obj)
{
  if (!obj)
    return;

  g_free (obj->username);
  g_free (obj->content);
  g_free (obj->object);
  g_free (obj->safe);
  g_free (obj->folder);
  g_free (obj);
}

/**
 * @brief Builds a query string to get a CyberArk object.
 *
 * @param[in] conn   Active connector to CyberArk credential store.
 * @param[in] safe   The safe name.
 * @param[in] folder The folder name.
 * @param[in] object The object name.
 *
 * @return A newly allocated query string. Must be freed by the caller.
 */
static gchar *
cyberark_build_query_string (cyberark_connector_t conn, const gchar *safe,
                             const gchar *folder, const gchar *object)
{

  if (!conn)
    {
      g_warning ("%s: Connector is NULL", __func__);
      return NULL;
    }

  if (conn->app_id == NULL)
    {
      g_warning ("%s: Application ID is NULL", __func__);
      return NULL;
    }

  GString *query = g_string_new ("");
  g_string_append_printf (query, "?AppID=%s", conn->app_id);

  if (object && *object)
    {
      g_string_append_printf (query,
                              "&Query=object=%s",
                              object);
    }
  else
    {
      g_warning ("%s: Object name is missing", __func__);
      g_string_free (query, TRUE);
      return NULL;
    }

  if (safe && *safe)
    {
      g_string_append_printf (query,
                              ";safe=%s",
                              safe);
    }

  if (folder && *folder)
    {
      g_string_append_printf (query,
                              ";folder=%s",
                              folder);
    }

  return g_string_free (query, FALSE);
}

/**
 * @brief Parses a CyberArk object from a JSON representation.
 *
 * @param[in] object_json  cJSON object representing the CyberArk object.
 *
 * @return Parsed `cyberark_object_t` on success, NULL on failure. Has to be
 *         freed with `cyberark_object_free()`.
 */
static cyberark_object_t
parse_cyberark_object (cJSON *object_json)
{

  if (!object_json || !cJSON_IsObject (object_json))
    {
      g_warning ("%s: Invalid JSON object", __func__);
      return NULL;
    }

  cyberark_object_t cyberark_object = cyberark_object_new ();

  if (!cyberark_object)
    {
      g_warning ("%s: Failed to create CyberArk object", __func__);
      return NULL;
    }

  const gchar *username = gvm_json_obj_str (object_json, "username");
  const gchar *content = gvm_json_obj_str (object_json, "content");
  const gchar *object = gvm_json_obj_str (object_json, "object");
  const gchar *safe = gvm_json_obj_str (object_json, "safe");
  const gchar *folder = gvm_json_obj_str (object_json, "folder");
  const gchar *password_change_in_process = 
    gvm_json_obj_str (object_json, "passwordchangeinprocess");
  
  if (!content || !username || !password_change_in_process)
    {
      g_warning ("%s: Missing required fields in JSON object", __func__);
      cyberark_object_free (cyberark_object);
      return NULL;
    }

  cyberark_object->username = g_strdup (username);
  cyberark_object->content = g_strdup (content);
  cyberark_object->password_change_in_process 
    = strcasecmp (password_change_in_process, "true") == 0 ? 1 : 0;
  cyberark_object->object = object ? g_strdup (object) : NULL;
  cyberark_object->safe = safe ? g_strdup (safe) : NULL;
  cyberark_object->folder = folder ? g_strdup (folder) : NULL;

  return cyberark_object;
}

/**
 * @brief Parses a CyberArk error from HTTP response data.
 *
 * @param[in] response_data  The HTTP response data containing the error.
 *
 * @return Parsed error codr or NULL on failure.
 */
static gchar *
parse_cyberark_error (gchar *response_data)
{
  if (!response_data)
    {
      g_warning ("%s: Response data is NULL", __func__);
      return NULL;
    }

  cJSON *error_json = cJSON_Parse (response_data);
  if (!error_json || !cJSON_IsObject (error_json))
    {
      g_warning ("%s: Failed to parse JSON error", __func__);
      if (error_json)
        cJSON_Delete (error_json);
      return NULL;
    }
  const gchar *error_code = gvm_json_obj_str (error_json, "ErrorCode");
  if (error_code)
    {
      gchar *error_msg = g_strdup (error_code);
      cJSON_Delete (error_json);
      return error_msg;
    }
  cJSON_Delete (error_json);
  return NULL;
}

/**
 * @brief Fetches an account object from CyberArk credential store.
 *
 * @param[in] conn   Active connector to CyberArk credential store.
 * @param[in] safe   The safe name.
 * @param[in] folder The folder name.
 * @param[in] object The object name.
 *
 * @return CyberArk object on success, NULL on failure. Has to be freed with
 *         `cyberark_object_free()`.
 */
cyberark_object_t
cyberark_get_object (cyberark_connector_t conn, const gchar *safe,
                     const gchar *folder, const gchar *object)
{
  if (!conn)
    {
      g_warning ("%s: Connector is NULL", __func__);
      return NULL;
    }

  if (conn->app_id == NULL)
    {
      g_warning ("%s: Application ID is NULL", __func__);
      return NULL;
    }

  gchar *query_str = cyberark_build_query_string (conn, safe, folder, object);

  if (!query_str)
    {
      g_warning ("%s: Failed to build query string", __func__);
      return NULL;
    }

  gchar *path = g_strdup_printf ("/Accounts/%s", query_str);
  g_free (query_str);

  gvm_http_response_t *response = cyberark_send_request (
    conn, GET, path, NULL, NULL);

  g_free (path);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return NULL;
    }

  if (response->http_status != 200)
    {
      g_warning ("%s: Received HTTP status %ld", __func__,
                 response->http_status);
      gchar *error_code = parse_cyberark_error (response->data);
      if (error_code)
        {
          g_warning ("%s: CyberArk error code: %s", __func__, error_code);
          g_free (error_code);
        }
      gvm_http_response_free (response);
      return NULL;
    }

  cJSON *object_json = cJSON_Parse (response->data);
  if (!object_json || !cJSON_IsObject (object_json))
    {
      g_warning ("%s: Failed to parse JSON object", __func__);
      if (object_json)
        cJSON_Delete (object_json);
      gvm_http_response_free (response);
      return NULL;
    }

  cyberark_object_t cyberark_object = parse_cyberark_object (object_json);

  if (!cyberark_object)
    {
      g_warning ("%s: Failed to parse CyberArk object", __func__);
      cJSON_Delete (object_json);
      gvm_http_response_free (response);
      return NULL;
    }

  cJSON_Delete (object_json);
  gvm_http_response_free (response);

  return cyberark_object;
}

/**
 * @brief Verifies the connection to the CyberArk credential store.
 *
 * @param[in] conn          Active connector to the credential store
 * @param[in] safe          Safe name used for verification
 * @param[in] folder        Folder name used for verification
 * @param[in] object        Object name used for verification 
 *
 * @return 0 on connection success, 1 on connection failure, -1 on error.
 */
int
cyberark_verify_connection (cyberark_connector_t conn, const gchar *safe,
                            const gchar *folder, const gchar *object)
{
  if (!conn)
    {
      g_warning ("%s: Connector is NULL", __func__);
      return -1;
    }

 gchar *query_str = cyberark_build_query_string (conn, safe, folder, object);

  if (!query_str)
    {
      g_warning ("%s: Failed to build query string", __func__);
      return -1;
    }

  gchar *path = g_strdup_printf ("/Accounts/%s", query_str);

  g_free (query_str);

  gvm_http_response_t *response = cyberark_send_request (
    conn, GET, path, NULL, NULL);

  g_free (path);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return -1;
    }

  /*
    * For now, consider connection verified if the HTTP response is 200 or 404
    * in case a dummy object is used. Other status codes indicate a problem
    * with the connection or authentication.
  */

  int ret = 1;
  if (response->http_status == 200)
    {
      ret = 0;
    }
  else
    {
      g_debug ("%s: Received HTTP status %ld", __func__, response->http_status);
      gchar *error_code = parse_cyberark_error (response->data);
      if (error_code)
        {
          g_debug ("%s: CyberArk error code: %s", __func__, error_code);
          if (response->http_status == 404 && g_strcmp0 (error_code, "APPAP004E") == 0)
            ret = 0;
          g_free (error_code);
        }
    }
  gvm_http_response_free (response);
  return ret;
}