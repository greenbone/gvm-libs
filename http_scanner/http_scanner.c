/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file httpscanner.c
 * @brief API for communication with an HTTP scanner.
 *
 */

#include "http_scanner.h"

#include "../http/httputils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm http_scanner"

#define RESP_CODE_ERR -1
#define RESP_CODE_OK 0

/**  @brief Struct holding the data for connecting with HTTP scanner. */
struct http_scanner_connector
{
  gchar *ca_cert;     /**< Path to the directory holding the CA certificate. */
  gchar *cert;        /**< Client certificate. */
  gchar *key;         /**< Client key. */
  gchar *apikey;      /**< API key for authentication. */
  gchar *host;        /**< server hostname. */
  gchar *scan_prefix; /**< Scan prefix for scanning endpoint. */
  gchar *scan_id;     /**< Scan ID. */
  int port;           /**< server port. */
  gchar *protocol;    /**< server protocol (http or https). */
  gvm_http_response_stream_t stream_resp; /** For response. */
};

/** @brief Initialize an HTTP scanner connector.
 *
 *  @return An HTTP scanner connector struct. It must be freed
 *  with http_scanner_connector_free().
 */
http_scanner_connector_t
http_scanner_connector_new (void)
{
  http_scanner_connector_t connector;
  gvm_http_response_stream_t stream;

  connector = g_malloc0 (sizeof (struct http_scanner_connector));
  stream = gvm_http_response_stream_new ();
  connector->stream_resp = stream;

  return connector;
}

/** @brief Build an HTTP scanner connector.
 *
 *  Receive option name and value to build the HTTP scanner connector.
 *
 *  @param conn   struct holding the HTTP scanner connector information.
 *  @param opt    option to set.
 *  @param val    value to set.
 *
 *  @return Return OK on success, otherwise error.
 */
http_scanner_error_t
http_scanner_connector_builder (http_scanner_connector_t conn,
                                http_scanner_conn_opt_t opt, const void *val)
{
  if (conn == NULL)
    conn = http_scanner_connector_new ();

  if (opt < HTTP_SCANNER_CA_CERT || opt > HTTP_SCANNER_SCAN_PREFIX)
    return HTTP_SCANNER_INVALID_OPT;

  if (val == NULL)
    return HTTP_SCANNER_INVALID_VALUE;

  switch (opt)
    {
    case HTTP_SCANNER_CA_CERT:
      conn->ca_cert = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_CERT:
      conn->cert = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_KEY:
      conn->key = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_API_KEY:
      conn->apikey = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_PROTOCOL:
      if (g_strcmp0 ((char *) val, "http") != 0
          && g_strcmp0 ((char *) val, "https") != 0)
        return HTTP_SCANNER_INVALID_VALUE;
      conn->protocol = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_HOST:
      conn->host = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_SCAN_ID:
      conn->scan_id = g_strdup ((const gchar *) val);
      break;
    case HTTP_SCANNER_SCAN_PREFIX:
      conn->scan_prefix = g_strdup ((char *) val);
      break;
    case HTTP_SCANNER_PORT:
    default:
      conn->port = *((int *) val);
      break;
    };

  return HTTP_SCANNER_OK;
}

/** @brief Free an HTTP scanner connector.
 *
 *  Free all the memory allocated for the HTTP scanner connector.
 *
 *  @param conn struct holding the HTTP scanner connector information.
 *
 *  @return Return HTTP_SCANNER_OK.
 */
http_scanner_error_t
http_scanner_connector_free (http_scanner_connector_t conn)
{
  if (conn == NULL)
    return HTTP_SCANNER_OK;

  g_free (conn->ca_cert);
  g_free (conn->cert);
  g_free (conn->key);
  g_free (conn->apikey);
  g_free (conn->protocol);
  g_free (conn->host);
  g_free (conn->scan_id);
  g_free (conn->scan_prefix);
  gvm_http_response_stream_free (conn->stream_resp);
  g_free (conn);
  conn = NULL;

  return HTTP_SCANNER_OK;
}

/**
 * @brief Free an HTTP scanner response struct.
 *
 * @param resp Response to be freed.
 */
void
http_scanner_response_cleanup (http_scanner_resp_t resp)
{
  if (resp == NULL)
    return;

  g_free (resp->body);
  g_free (resp->header);
  g_free (resp);
  resp = NULL;
}

/**
 * @brief Initialize custom headers for the HTTP request.
 *
 * @param apikey      API key to be included in the headers.
 * @param contenttype If TRUE, include Content-Type header as application/json.
 *
 * @return Pointer to the initialized headers structure.
 */
static gvm_http_headers_t *
init_customheader (const gchar *apikey, gboolean contenttype)
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

  // Set Content-Type
  if (contenttype)
    {
      if (!gvm_http_add_header (headers, "Content-Type: application/json"))
        g_warning ("%s: Not possible to set Content-Type", __func__);
    }

  return headers;
}

/**
 * @brief Initialized an curl multiperform handler which allows fetch feed
 * metadata chunk by chunk.
 *
 * @param conn Connector struct with the data necessary for the connection
 * @param path The resource path.
 *
 * @return The response.
 */
http_scanner_resp_t
http_scanner_init_request_multi (http_scanner_connector_t conn,
                                 const gchar *path)
{
  http_scanner_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  response = g_malloc0 (sizeof (struct http_scanner_response));

  if (!conn)
    {
      g_warning ("%s: Invalid connector", __func__);
      response->code = RESP_CODE_ERR;
      response->body =
        g_strdup ("{\"error\": \"Missing HTTP scanner connector\"}");
      return response;
    }

  gchar *url = g_strdup_printf ("%s://%s:%d%s", conn->protocol, conn->host,
                                conn->port, path);

  customheader = init_customheader (conn->apikey, FALSE);

  if (!conn->stream_resp)
    {
      conn->stream_resp = g_malloc0 (sizeof (struct gvm_http_response_stream));
    }

  gvm_http_multi_t *multi_handle = gvm_http_multi_new ();
  if (!multi_handle)
    {
      g_warning ("%s: Failed to initialize curl multi-handle", __func__);
      g_free (url);
      response->code = RESP_CODE_ERR;
      response->body =
        g_strdup ("{\"error\": \"Failed to initialize multi-handle\"}");
      return response;
    }

  // Initialize request using curlutils
  gvm_http_t *http = gvm_http_new (url, GET, NULL, customheader, conn->ca_cert,
                                   conn->cert, conn->key, conn->stream_resp);

  g_free (url);

  // Check if curl handle was created properly
  if (!http || !http->handler)
    {
      g_warning ("%s: Failed to initialize curl request", __func__);
      gvm_http_headers_free (customheader);
      gvm_http_multi_free (multi_handle);
      response->code = RESP_CODE_ERR;
      response->body =
        g_strdup ("{\"error\": \"Failed to initialize CURL request\"}");
      return response;
    }

  gvm_http_multi_result_t multi_add_result =
    gvm_http_multi_add_handler (multi_handle, http);
  if (multi_add_result != GVM_HTTP_OK)
    {
      g_warning ("%s: Failed to add CURL handle to multi", __func__);
      gvm_http_multi_handler_free (multi_handle, http);
      gvm_http_headers_free (customheader);
      gvm_http_multi_free (multi_handle);
      response->code = RESP_CODE_ERR;
      response->body =
        g_strdup ("{\"error\": \"Failed to add CURL handle to multi\"}");
      return response;
    }

  conn->stream_resp->multi_handler = multi_handle;
  conn->stream_resp->multi_handler->headers = customheader;

  g_debug ("%s: Multi handle initialized successfully", __func__);

  response->code = RESP_CODE_OK;
  return response;
}

/**
 * @brief Process the multi handle to fetch data.
 *
 * This function must be called until the
 * return value is 0, meaning there is no more data to fetch.
 *
 * @param conn Connector struct with the data necessary for the connection.
 * @param timeout Maximum time in milliseconds to wait for activity.
 *
 * @return greather than 0 if the handler is still getting data. 0 if the
 * transmision finished. -1 on error
 */
int
http_scanner_process_request_multi (http_scanner_connector_t conn, int timeout)
{
  static int running = 0;

  if (!conn || !conn->stream_resp)
    {
      g_warning ("%s: Invalid connector", __func__);
      return -1;
    }

  gvm_http_multi_t *multi = conn->stream_resp->multi_handler;
  if (!multi || !multi->handler)
    {
      g_warning ("%s: Invalid multi-handler", __func__);
      return -1;
    }

  gvm_http_multi_result_t mc = gvm_http_multi_perform (multi, &running);

  if (mc == GVM_HTTP_OK && running)
    {
      /* wait for activity, timeout, or "nothing" */
      if (gvm_http_multi_poll (multi, timeout) != GVM_HTTP_OK)
        {
          g_warning ("%s: error polling the multi-handle for activity",
                     __func__);
          return -1;
        }
    }

  return running;
}

/**
 * @brief Maps http_scanner_method_t to gvm_http_method_t.
 *
 * @param method The HTTP scanner method to map.
 *
 * @return The corresponding gvm_http_method_t value.
 */
static gvm_http_method_t
get_http_method (http_scanner_method_t method)
{
  switch (method)
    {
    case HTTP_SCANNER_GET:
      return GET;
    case HTTP_SCANNER_POST:
      return POST;
    case HTTP_SCANNER_PUT:
      return PUT;
    case HTTP_SCANNER_DELETE:
      return DELETE;
    case HTTP_SCANNER_HEAD:
      return HEAD;
    case HTTP_SCANNER_PATCH:
      return PATCH;
    default:
      return GET;
    }
}

/**
 * @brief Sends an HTTP(S) request using the specified parameters.
 *
 * @param conn The `http_scanner_connector_t` containing server and certificate
 * details.
 * @param method The HTTP method (GET, POST, etc.).
 * @param path The resource path (e.g., `/scans`).
 * @param data The request payload (if applicable).
 * @param custom_headers Additional request headers.
 * @param header_name The header key to extract from the response.
 *
 * @return `http_scanner_resp_t` containing response status, body, and header
 * value.
 */
http_scanner_resp_t
http_scanner_send_request (http_scanner_connector_t conn,
                           http_scanner_method_t method, const gchar *path,
                           const gchar *data, const gchar *header_name)
{
  http_scanner_resp_t response =
    g_malloc0 (sizeof (struct http_scanner_response));
  response->code = RESP_CODE_ERR;
  response->body = NULL;
  response->header = NULL;

  if (!conn)
    {
      g_warning ("%s: Invalid connector", __func__);
      response->body =
        g_strdup ("{\"error\": \"Missing HTTP scanner connector\"}");
      return response;
    }

  gchar *url = g_strdup_printf ("%s://%s:%d%s", conn->protocol, conn->host,
                                conn->port, path);

  if (!conn->stream_resp)
    {
      conn->stream_resp = g_malloc0 (sizeof (struct gvm_http_response_stream));
    }

  gvm_http_headers_t *custom_headers =
    init_customheader (conn->apikey, data ? TRUE : FALSE);

  // Send request
  gvm_http_response_t *http_response =
    gvm_http_request (url, get_http_method (method), data, custom_headers,
                      conn->ca_cert, conn->cert, conn->key, conn->stream_resp);

  // Check for request errors
  if (http_response->http_status == -1)
    {
      g_warning ("%s: Error performing CURL request", __func__);
      response->body = g_strdup ("{\"error\": \"Error sending request\"}");
      gvm_http_response_free (http_response);
      g_free (url);
      gvm_http_headers_free (custom_headers);
      return response;
    }

  // Populate response struct
  response->code = (int) http_response->http_status;
  response->body = g_strdup (
    http_response->data ? http_response->data : "{\"error\": \"No response\"}");

  // Extract specific header if requested
  if (header_name)
    {
      struct curl_header *hname;
      if (curl_easy_header (http_response->http->handler, header_name, 0,
                            CURLH_HEADER, -1, &hname)
          == CURLHE_OK)
        {
          response->header = g_strdup (hname->value);
        }
    }

  // Cleanup
  gvm_http_response_free (http_response);
  g_free (url);
  gvm_http_headers_free (custom_headers);

  return response;
}

/**
 * @brief Request HEAD.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response containing the header information.
 */
http_scanner_resp_t
http_scanner_get_version (http_scanner_connector_t conn)
{
  http_scanner_resp_t response = NULL;

  response =
    http_scanner_send_request (conn, HTTP_SCANNER_HEAD, "/", NULL, NULL);

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Builds the path prefix for scan endpoints.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return The constructed path prefix. Has to be freed by the caller.
 */
static GString *
build_path_prefix (http_scanner_connector_t conn)
{
  GString *path = g_string_new ("");
  if (conn != NULL && conn->scan_prefix != NULL && conn->scan_prefix[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_prefix);
    }
  g_string_append (path, "/scans");
  return path;
}

/**
 * @Brief Create a scan.
 *
 * @param conn Connector struct with the data necessary for the connection.
 * @param data String containing the scan config in JSON format.
 *
 * @return Response Struct containing the response.
 * If created successfully, the scan ID is stored in the connector.
 */
http_scanner_resp_t
http_scanner_create_scan (http_scanner_connector_t conn, gchar *data)
{
  http_scanner_resp_t response = NULL;
  cJSON *parser = NULL;
  GString *path = build_path_prefix (conn);

  response =
    http_scanner_send_request (conn, HTTP_SCANNER_POST, path->str, data, NULL);

  g_string_free (path, TRUE);

  if (response->code == RESP_CODE_ERR)
    {
      if (response->body == NULL)
        response->body = g_strdup ("{\"error\": \"Creating the scan.\"}");
      g_warning ("%s: Error creating the scan.", __func__);
      http_scanner_reset_stream (conn);
      return response;
    }

  // Get the Scan ID
  parser = cJSON_Parse (http_scanner_stream_str (conn));
  if (!parser)
    {
      const gchar *error_ptr = cJSON_GetErrorPtr ();
      g_warning ("%s: Error parsing json string to get the scan ID", __func__);
      if (error_ptr != NULL)
        {
          response->body = g_strdup_printf ("{\"error\": \"%s\"}", error_ptr);
          g_warning ("%s: %s", __func__, error_ptr);
        }
      else
        {
          response->body = g_strdup (
            "{\"error\": \"Parsing json string to get the scan ID\"}");
        }
      response->code = RESP_CODE_ERR;
      cJSON_Delete (parser);
      http_scanner_reset_stream (conn);
      return response;
    }

  conn->scan_id = g_strdup (cJSON_GetStringValue (parser));

  cJSON_Delete (parser);
  response->body = g_strdup (http_scanner_stream_str (conn));
  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Start a scan.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_start_scan (http_scanner_connector_t conn)
{
  http_scanner_resp_t response;
  GString *path = build_path_prefix (conn);

  if (conn != NULL && conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
    }
  else
    {
      response = g_malloc0 (sizeof (struct http_scanner_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = http_scanner_send_request (conn, HTTP_SCANNER_POST, path->str,
                                        "{\"action\": \"start\"}", NULL);

  g_string_free (path, TRUE);

  if (response->code == RESP_CODE_ERR)
    {
      if (response->body == NULL)
        response->body = g_strdup ("{\"error\": \"Starting the scan.\"}");
      g_warning ("%s: Error starting the scan.", __func__);
      return response;
    }

  response->body = g_strdup (http_scanner_stream_str (conn));
  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Stop a scan.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_stop_scan (http_scanner_connector_t conn)
{
  http_scanner_resp_t response;
  GString *path = build_path_prefix (conn);

  if (conn != NULL && conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
    }
  else
    {
      response = g_malloc0 (sizeof (struct http_scanner_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = http_scanner_send_request (conn, HTTP_SCANNER_POST, path->str,
                                        "{\"action\": \"stop\"}", NULL);

  g_string_free (path, TRUE);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Get results of a scan.
 *
 * @param conn  Connector struct with the data necessary for the connection.
 * @param first First result index to retrieve.
 * @param last  Last result index to retrieve.
 */
http_scanner_resp_t
http_scanner_get_scan_results (http_scanner_connector_t conn, long first,
                               long last)
{
  http_scanner_resp_t response = NULL;
  GString *path = build_path_prefix (conn);

  if (conn != NULL && conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
      if (last > first)
        g_string_append_printf (path, "/results?range%ld-%ld", first, last);
      else if (last < first)
        g_string_append_printf (path, "/results?range=%ld", first);
      else
        g_string_append (path, "/results");
    }
  else
    {
      response = g_malloc0 (sizeof (struct http_scanner_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response =
    http_scanner_send_request (conn, HTTP_SCANNER_GET, path->str, NULL, NULL);
  g_string_free (path, TRUE);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      g_warning ("%s: Not possible to get scan results", __func__);
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan results\"}");
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Create a new result.
 *
 * @param id                     Result ID.
 * @param type                   Result type.
 * @param ip_address             IP address.
 * @param hostname               Hostname.
 * @param oid                    OID.
 * @param port                   Port.
 * @param protocol               Protocol.
 * @param message                Message.
 * @param detail_name            Detail name.
 * @param detail_value           Detail value.
 * @param detail_source_type     Detail source type.
 * @param detail_source_name     Detail source name.
 * @param detail_source_description Detail source description.
 */
http_scanner_result_t
http_scanner_result_new (unsigned long id, gchar *type, gchar *ip_address,
                         gchar *hostname, gchar *oid, gchar *port,
                         gchar *protocol, gchar *message, gchar *detail_name,
                         gchar *detail_value, gchar *detail_source_type,
                         gchar *detail_source_name,
                         gchar *detail_source_description)
{
  http_scanner_result_t result =
    g_malloc0 (sizeof (struct http_scanner_result));

  result->id = id;
  result->type = g_strdup (type);
  result->ip_address = g_strdup (ip_address);
  result->hostname = g_strdup (hostname);
  result->oid = g_strdup (oid);
  result->message = g_strdup (message);
  result->detail_name = g_strdup (detail_name);
  result->detail_value = g_strdup (detail_value);
  result->detail_source_name = g_strdup (detail_source_name);
  result->detail_source_type = g_strdup (detail_source_type);
  result->detail_source_description = g_strdup (detail_source_description);

  if (!g_strcmp0 (type, "host_detail"))
    result->port = g_strdup ("general/Host_Details");
  else if (port == NULL || (!g_strcmp0 (port, "0") && protocol))
    result->port = g_strdup_printf ("general/%s", protocol);
  else if (protocol)
    result->port = g_strdup_printf ("%s/%s", port, protocol);
  else
    result->port = g_strdup_printf ("general/tcp");

  return result;
}

/**
 * @brief Get a string member from a result.
 *
 * @param result Result object.
 * @param member Member to retrieve.
 *
 * @return Value of the member or NULL if not found.
 */
char *
http_scanner_get_result_member_str (http_scanner_result_t result,
                                    http_scanner_result_member_string_t member)
{
  if (!result)
    return NULL;
  switch (member)
    {
    case TYPE:
      return result->type;

    case IP_ADDRESS:
      return result->ip_address;
    case HOSTNAME:
      return result->hostname;
    case OID:
      return result->oid;
    case PORT:
      return result->port;
    case MESSAGE:
      return result->message;
    case DETAIL_NAME:
      return result->detail_name;
    case DETAIL_VALUE:
      return result->detail_value;
    case DETAIL_SOURCE_NAME:
      return result->detail_source_name;
    case DETAIL_SOURCE_TYPE:
      return result->detail_source_type;
    case DETAIL_SOURCE_DESCRIPTION:
      return result->detail_source_description;
    default:
      return NULL;
    }
}

/**
 * @brief Get an integer member from a result.
 *
 * @param result Result object.
 * @param member Member to retrieve.
 *
 * @return Value of the member or -1 if not found.
 */
int
http_scanner_get_result_member_int (http_scanner_result_t result,
                                    http_scanner_result_member_int_t member)
{
  if (!result)
    return -1;

  switch (member)
    {
    case ID:
      return result->id;
    default:
      return -1;
    }
}

/**
 * @brief Parse the results of a scan.
 *
 * @param body    Body containing the results.
 * @param results Pointer to a GSList to store the parsed results.
 *
 * @return 200 on success, otherwise -1.
 */
static int
parse_results (const gchar *body, GSList **results)
{
  cJSON *parser;
  cJSON *result_obj = NULL;
  const gchar *err = NULL;
  http_scanner_result_t result = NULL;
  int ret = -1;

  parser = cJSON_Parse (body);
  if (parser == NULL)
    {
      err = cJSON_GetErrorPtr ();
      goto res_cleanup;
    }
  if (!cJSON_IsArray (parser))
    {
      // No results. No information.
      goto res_cleanup;
    }

  cJSON_ArrayForEach (result_obj, parser)
  {
    cJSON *item;
    gchar *port = NULL;
    gchar *detail_name = NULL;
    gchar *detail_value = NULL;
    gchar *detail_source_type = NULL;
    gchar *detail_source_name = NULL;
    gchar *detail_source_description = NULL;

    if (!cJSON_IsObject (result_obj))
      // error
      goto res_cleanup;

    item = cJSON_GetObjectItem (result_obj, "detail");
    if (item != NULL && cJSON_IsObject (item))
      {
        cJSON *detail_obj = NULL;

        detail_name = gvm_json_obj_str (item, "name");
        detail_value = gvm_json_obj_str (item, "value");

        detail_obj = cJSON_GetObjectItem (item, "source");
        if (detail_obj && cJSON_IsObject (detail_obj))
          {
            detail_source_type = gvm_json_obj_str (detail_obj, "type");
            detail_source_name = gvm_json_obj_str (detail_obj, "name");
            detail_source_description =
              gvm_json_obj_str (detail_obj, "description");
          }
      }
    port = g_strdup_printf ("%d", gvm_json_obj_int (result_obj, "port")),

    result = http_scanner_result_new (
      gvm_json_obj_double (result_obj, "id"),
      gvm_json_obj_str (result_obj, "type"),
      gvm_json_obj_str (result_obj, "ip_address"),
      gvm_json_obj_str (result_obj, "hostname"),
      gvm_json_obj_str (result_obj, "oid"), port,
      gvm_json_obj_str (result_obj, "protocol"),
      gvm_json_obj_str (result_obj, "message"), detail_name, detail_value,
      detail_source_type, detail_source_name, detail_source_description);

    g_free (port);
    *results = g_slist_append (*results, result);
    ret = 200;
  }

res_cleanup:
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse scan results. Reason: %s", __func__, err);
    }
  cJSON_Delete (parser);

  return ret;
}

/**
 * @brief Parse the results of a scan.
 *
 * @param conn    Connector struct with the data necessary for the connection
 * @param first   First result index to retrieve.
 * @param last    Last result index to retrieve.
 * @param results Pointer to a GSList to store the parsed results.
 *
 * @return 200 on success, otherwise error code.
 */
int
http_scanner_parsed_results (http_scanner_connector_t conn, unsigned long first,
                             unsigned long last, GSList **results)
{
  int ret;
  http_scanner_resp_t resp;

  resp = http_scanner_get_scan_results (conn, first, last);
  if (resp->code == 200)
    ret = parse_results (resp->body, results);
  else
    ret = resp->code;

  http_scanner_response_cleanup (resp);

  return ret;
}

/**
 * @brief Free a scan result.
 *
 * @param result Result to be freed.
 */
void
http_scanner_result_free (http_scanner_result_t result)
{
  if (result == NULL)
    return;

  g_free (result->type);
  g_free (result->ip_address);
  g_free (result->hostname);
  g_free (result->oid);
  g_free (result->port);
  g_free (result->message);
  g_free (result->detail_name);
  g_free (result->detail_value);
  g_free (result->detail_source_name);
  g_free (result->detail_source_type);
  g_free (result->detail_source_description);
  g_free (result);
  result = NULL;
}

/**
 * @brief Get the status of a scan.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_get_scan_status (http_scanner_connector_t conn)
{
  http_scanner_resp_t response;
  GString *path = build_path_prefix (conn);

  if (conn != NULL && conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
      g_string_append (path, "/status");
    }
  else
    {
      response = g_malloc0 (sizeof (struct http_scanner_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response =
    http_scanner_send_request (conn, HTTP_SCANNER_GET, path->str, NULL, NULL);
  g_string_free (path, TRUE);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan status\"}");
      g_warning ("%s: Not possible to get scan status", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Delete a scan.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_delete_scan (http_scanner_connector_t conn)
{
  http_scanner_resp_t response;
  GString *path = build_path_prefix (conn);

  if (conn != NULL && conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
    }
  else
    {
      response = g_malloc0 (sizeof (struct http_scanner_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = http_scanner_send_request (conn, HTTP_SCANNER_DELETE, path->str,
                                        NULL, NULL);

  g_string_free (path, TRUE);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to delete scan.\"}");
      g_warning ("%s: Not possible to delete scan", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Get health alive information.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_get_health_alive (http_scanner_connector_t conn)
{
  http_scanner_resp_t response = NULL;

  response = http_scanner_send_request (conn, HTTP_SCANNER_GET, "/health/alive",
                                        NULL, NULL);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Get health ready information.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_get_health_ready (http_scanner_connector_t conn)
{
  http_scanner_resp_t response = NULL;

  response = http_scanner_send_request (conn, HTTP_SCANNER_GET, "/health/ready",
                                        NULL, "feed-version");

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Get health started information.
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return Response Struct containing the response.
 */
http_scanner_resp_t
http_scanner_get_health_started (http_scanner_connector_t conn)
{
  http_scanner_resp_t response = NULL;

  response = http_scanner_send_request (conn, HTTP_SCANNER_GET,
                                        "/health/started", NULL, NULL);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/** @brief Get the value from an object or error.
 *
 *  @return 0 on success, -1 on error.
 */
static int
get_member_value_or_fail (cJSON *reader, const gchar *member)
{
  int ret;

  if (gvm_json_obj_check_int (reader, member, &ret))
    return -1;

  return ret;
}

/** @brief Return the scan progress.
 *
 *  @param conn     HTTP scanner connector data
 *  @param response If not NULL, use this response instead of requesting a new
 *                  one.
 *
 *  @return The progress percentage (0-100), -1 on error, -2 if the scan is not
 *          found (404).
 */
static int
http_scanner_get_scan_progress_ext (http_scanner_connector_t conn,
                                    http_scanner_resp_t response)
{
  cJSON *parser;
  cJSON *reader = NULL;
  const gchar *err = NULL;
  int all = 0, excluded = 0, dead = 0, alive = 0, queued = 0, finished = 0;
  int running_hosts_progress_sum = 0;

  http_scanner_resp_t resp;
  int progress = -1;

  if (!response && !conn)
    return -1;

  if (response == NULL)
    resp = http_scanner_get_scan_status (conn);
  else
    resp = response;

  if (resp->code == 404)
    return -2;
  else if (resp->code != 200)
    return -1;

  parser = cJSON_Parse (resp->body);
  if (!parser)
    {
      err = cJSON_GetErrorPtr ();
      goto cleanup;
    }

  reader = cJSON_GetObjectItem (parser, "host_info");
  if (reader == NULL)
    {
      goto cleanup;
    }
  if (!cJSON_IsObject (reader))
    {
      // Scan still not started. No information.
      progress = 0;
      goto cleanup;
    }

  // read general hosts count
  all = get_member_value_or_fail (reader, "all");
  excluded = get_member_value_or_fail (reader, "excluded");
  dead = get_member_value_or_fail (reader, "dead");
  alive = get_member_value_or_fail (reader, "alive");
  queued = get_member_value_or_fail (reader, "queued");
  finished = get_member_value_or_fail (reader, "finished");

  // read progress of single running hosts
  cJSON *scanning;
  scanning = cJSON_GetObjectItem (reader, "scanning");
  if (scanning != NULL && cJSON_IsObject (scanning))
    {
      cJSON *host = scanning->child;
      while (host)
        {
          running_hosts_progress_sum += cJSON_GetNumberValue (host);
          host = host->next;
        }
    }

  if (all < 0 || excluded < 0 || dead < 0 || alive < 0 || queued < 0
      || finished < 0)
    {
      goto cleanup;
    }

  if ((all + finished - dead) > 0)
    progress = (running_hosts_progress_sum + 100 * (alive + finished))
               / (all + finished - dead);
  else
    progress = 0;

cleanup:
  if (err != NULL)
    g_warning ("%s: Unable to parse scan status. Reason: %s", __func__, err);
  cJSON_Delete (parser);

  return progress;
}

/** @brief Return the scan progress.
 *
 *  @param conn HTTP scanner connector data.
 *
 *  @return The progress percentage (0-100), -1 on error, -2 if the scan is not
 *          found (404).
 */
int
http_scanner_get_scan_progress (http_scanner_connector_t conn)
{
  return http_scanner_get_scan_progress_ext (conn, NULL);
}

/**
 * @brief Get the status code from HTTP scanner status string.
 *
 * @param status_val Status string from HTTP scanner.
 */
static http_scanner_status_t
get_status_code (const gchar *status_val)
{
  http_scanner_status_t status_code = HTTP_SCANNER_SCAN_STATUS_ERROR;

  if (g_strcmp0 (status_val, "stored") == 0)
    status_code = HTTP_SCANNER_SCAN_STATUS_STORED;
  else if (g_strcmp0 (status_val, "requested") == 0)
    status_code = HTTP_SCANNER_SCAN_STATUS_REQUESTED;
  else if (g_strcmp0 (status_val, "running") == 0)
    status_code = HTTP_SCANNER_SCAN_STATUS_RUNNING;
  else if (g_strcmp0 (status_val, "stopped") == 0)
    status_code = HTTP_SCANNER_SCAN_STATUS_STOPPED;
  else if (g_strcmp0 (status_val, "succeeded") == 0)
    status_code = HTTP_SCANNER_SCAN_STATUS_SUCCEEDED;
  else if (g_strcmp0 (status_val, "interrupted") == 0)
    status_code = HTTP_SCANNER_SCAN_STATUS_FAILED;

  return status_code;
}

/** @brief Parse the status of a scan.
 *
 *  @param body        Body containing the status.
 *  @param status_info Pointer to a struct to store the parsed status.
 *
 *  @return 0 on success, otherwise -1.
 */
static int
parse_status (const gchar *body, http_scanner_scan_status_t status_info)
{
  cJSON *parser;
  gchar *status_val = NULL;
  http_scanner_status_t status_code = HTTP_SCANNER_SCAN_STATUS_ERROR;

  if (!status_info)
    return -1;

  parser = cJSON_Parse (body);
  if (parser == NULL)
    return -1;

  if (gvm_json_obj_check_str (parser, "status", &status_val))
    {
      cJSON_Delete (parser);
      return -1;
    }

  status_code = get_status_code (status_val);

  status_info->status = status_code;
  status_info->end_time = gvm_json_obj_double (parser, "end_time");
  status_info->start_time = gvm_json_obj_double (parser, "start_time");
  cJSON_Delete (parser);

  return 0;
}

/** @brief Return a struct with the general scan status.
 *
 *  @param conn HTTP scanner connector data.
 *
 *  @return The data in a struct. The struct must be freed
 *          by the caller.
 */
http_scanner_scan_status_t
http_scanner_parsed_scan_status (http_scanner_connector_t conn)
{
  http_scanner_resp_t resp = NULL;
  int progress = -1;
  http_scanner_status_t status_code = HTTP_SCANNER_SCAN_STATUS_ERROR;
  http_scanner_scan_status_t status_info = NULL;

  resp = http_scanner_get_scan_status (conn);

  status_info = g_malloc0 (sizeof (struct http_scanner_scan_status));
  if (resp->code != 200 || parse_status (resp->body, status_info) == -1)
    {
      status_info->status = status_code;
      status_info->response_code = resp->code;
      http_scanner_response_cleanup (resp);
      return status_info;
    }

  progress = http_scanner_get_scan_progress_ext (NULL, resp);
  http_scanner_response_cleanup (resp);
  status_info->progress = progress;

  return status_info;
}

/**
 * @brief Get scan preferences.
 *
 * @param conn Connector struct with the data necessary for the connection.
 *
 * @return Response Struct containing the scan preferences.
 */
http_scanner_resp_t
http_scanner_get_scan_preferences (http_scanner_connector_t conn)
{
  http_scanner_resp_t response = NULL;
  GString *path = build_path_prefix (conn);

  g_string_append (path, "/preferences");

  response =
    http_scanner_send_request (conn, HTTP_SCANNER_GET, path->str, NULL, NULL);

  g_string_free (path, TRUE);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scans preferences.\"}");
      g_warning ("%s: Not possible to get scans_preferences", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Create a new HTTP scanner parameter.
 *
 * @return New HTTP scanner parameter.
 */
static http_scanner_param_t *
http_scanner_param_new (char *id, gchar *name, gchar *defval,
                        gchar *description, gchar *type, int mandatory)
{
  http_scanner_param_t *param = g_malloc0 (sizeof (http_scanner_param_t));

  param->id = id;
  param->defval = defval;
  param->description = description;
  param->name = name;
  param->mandatory = mandatory;
  param->type = type;
  return param;
}

/**
 * @brief Free an HTTP scanner parameter.
 *
 * @param param HTTP scanner parameter to destroy.
 */
void
http_scanner_param_free (http_scanner_param_t *param)
{
  if (!param)
    return;
  g_free (param->id);
  g_free (param->name);
  g_free (param->defval);
  g_free (param->description);
  g_free (param->type);
}

/**
 * @brief Get the parameter id.
 *
 * @param param HTTP scanner parameter.
 */
char *
http_scanner_param_id (http_scanner_param_t *param)
{
  if (!param)
    return NULL;

  return param->id;
}

/**
 * @brief Get the parameter name.
 *
 * @param param HTTP scanner parameter.
 */
char *
http_scanner_param_name (http_scanner_param_t *param)
{
  if (!param)
    return NULL;

  return param->defval;
}

/**
 * @brief Get the parameter description.
 *
 * @param param HTTP scanner parameter.
 */
char *
http_scanner_param_desc (http_scanner_param_t *param)
{
  if (!param)
    return NULL;

  return param->description;
}

/**
 * @brief Get the parameter type.
 *
 * @param param HTTP scanner parameter.
 */
char *
http_scanner_param_type (http_scanner_param_t *param)
{
  if (!param)
    return NULL;

  return param->type;
}

/**
 * @brief Get the parameter default.
 *
 * @param param HTTP scanner parameter.
 */
char *
http_scanner_param_default (http_scanner_param_t *param)
{
  if (!param)
    return NULL;

  return param->defval;
}

/**
 * @brief If the parameter is mandatory.
 *
 * @param param HTTP scanner parameter.
 */
int
http_scanner_param_mandatory (http_scanner_param_t *param)
{
  if (!param)
    return 0;

  return param->mandatory;
}

/**
 * @brief Get the scan preferences and parse them.
 *
 * @param conn   Connector struct with the data necessary for the connection.
 * @param params Pointer to a GSList to store the parsed parameters.
 *
 * @return 0 on success, otherwise -1.
 */
int
http_scanner_parsed_scans_preferences (http_scanner_connector_t conn,
                                       GSList **params)
{
  http_scanner_resp_t resp = NULL;
  cJSON *parser;
  cJSON *param_obj = NULL;
  int err = 0;

  resp = http_scanner_get_scan_preferences (conn);

  if (resp->code != 200)
    return -1;

  // No results. No information.
  parser = cJSON_Parse (resp->body);
  if (parser == NULL || !cJSON_IsArray (parser))
    {
      err = 1;
      goto prefs_cleanup;
    }

  cJSON_ArrayForEach (param_obj, parser)
  {
    gchar *defval = NULL, *param_type = NULL;
    http_scanner_param_t *param = NULL;
    int val, mandatory = 0;
    char buf[6];
    cJSON *item = NULL;

    item = cJSON_GetObjectItem (param_obj, "default");
    if (item != NULL)
      {
        if (cJSON_IsNumber (item))
          {
            val = item->valueint;
            g_snprintf (buf, sizeof (buf), "%d", val);
            defval = g_strdup (buf);
            param_type = g_strdup ("integer");
          }
        else if (cJSON_IsString (item))
          {
            defval = g_strdup (item->valuestring);
            param_type = g_strdup ("string");
          }
        else if (cJSON_IsBool (item))
          {
            if (cJSON_IsTrue (item))
              defval = g_strdup ("yes");
            else
              defval = g_strdup ("no");
            param_type = g_strdup ("boolean");
          }
        else
          {
            g_warning ("%s: Unable to parse scan preferences.", __func__);
            g_free (defval);
            g_free (param_type);
            continue;
          }
      }

    param = http_scanner_param_new (
      g_strdup (gvm_json_obj_str (param_obj, "id")),
      g_strdup (gvm_json_obj_str (param_obj, "name")), g_strdup (defval),
      g_strdup (gvm_json_obj_str (param_obj, "description")),
      g_strdup (param_type), mandatory);
    g_free (defval);
    g_free (param_type);
    *params = g_slist_append (*params, param);
  }

prefs_cleanup:
  http_scanner_response_cleanup (resp);
  cJSON_Delete (parser);
  if (err)
    {
      g_warning ("%s: Failed to parse scan preferences.", __func__);
      return -1;
    }

  return 0;
}

/** @brief Reset the response stream.
 *
 *  @param conn HTTP scanner connector data.
 */
void
http_scanner_reset_stream (http_scanner_connector_t conn)
{
  gvm_http_response_stream_reset (conn->stream_resp);
}

/** @brief Get the response stream data.
 *
 *  @param conn HTTP scanner connector data.
 *
 *  @return The response stream data.
 */
gchar *
http_scanner_stream_str (http_scanner_connector_t conn)
{
  return conn->stream_resp->data;
}

/** @brief Get the response stream length.
 *
 *  @param conn HTTP scanner connector data.
 *
 *  @return The response stream length.
 */
size_t
http_scanner_stream_len (http_scanner_connector_t conn)
{
  return conn->stream_resp->length;
}