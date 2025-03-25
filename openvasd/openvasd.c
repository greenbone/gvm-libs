/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Openvas Daemon communication.
 */

#include "openvasd.h"

#include "../base/array.h"
#include "../base/networking.h"
#include "../http/httputils.h"
#include "../util/json.h"

#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm ovd"

#define RESP_CODE_ERR -1
#define RESP_CODE_OK 0

/**
 * @brief Struct holding the data for connecting with openvasd.
 */
struct openvasd_connector
{
  gchar *ca_cert; /**< Path to the directory holding the CA certificate. */
  gchar *cert;    /**< Client certificate. */
  gchar *key;     /**< Client key. */
  gchar *apikey;  /**< API key for authentication. */
  gchar *server;  /**< original openvasd server URL. */
  gchar *host;    /**< server hostname. */
  gchar *scan_id; /**< Scan ID. */
  int port;       /**< server port. */
  gvm_http_response_stream_t stream_resp; /** For response */
};

/**
 * @brief Struct holding options for openvasd parameters.
 */
struct openvasd_param
{
  gchar *id;          /**< Parameter id. */
  gchar *name;        /**< Parameter name. */
  gchar *defval;      /**< Default value. */
  gchar *description; /**< Description. */
  gchar *type;        /**< Parameter type. */
  int mandatory;      /**< If mandatory. */
};

/**
 * @brief Struct credential information for openvasd.
 */
struct openvasd_credential
{
  gchar *type;           /**< Credential type */
  gchar *service;        /**< Service the credential is for */
  gchar *port;           /**< Port the credential is for */
  GHashTable *auth_data; /**< Authentication data (username, password, etc.)*/
};

/**
 * @brief Struct holding target information.
 */
struct openvasd_target
{
  gchar *scan_id;           /**  Scan ID */
  GSList *credentials;      /** Credentials to use in the scan */
  gchar *exclude_hosts;     /** String defining one or many hosts to exclude */
  gchar *hosts;             /** String defining one or many hosts to scan */
  gchar *ports;             /** String defining the ports to scan */
  gchar *finished_hosts;    /** String defining hosts to exclude as finished */
  gboolean icmp;            /** Alive test method icmp */
  gboolean tcp_syn;         /** Alive test method tcp_syn */
  gboolean tcp_ack;         /** Alive test method tcp_ack */
  gboolean arp;             /** Alive test method arp */
  gboolean consider_alive;  /** Alive test method consider alive */
  int reverse_lookup_unify; /** Value defining reverse_lookup_unify opt */
  int reverse_lookup_only;  /** Value defining reverse_lookup_only opt */
};

/**
 * @brief Struct holding vt information
 */
struct openvasd_vt_single
{
  gchar *vt_id;
  GHashTable *vt_values;
};

/** @brief Initialize an openvasd connector.
 *
 *  @return An openvasd connector struct. It must be freed
 *  with openvasd_connector_free()
 */
openvasd_connector_t
openvasd_connector_new (void)
{
  openvasd_connector_t connector;
  gvm_http_response_stream_t stream;

  connector = g_malloc0 (sizeof (struct openvasd_connector));
  stream = gvm_http_response_stream_new ();
  connector->stream_resp = stream;

  return connector;
}

/** @brief Build a openvasd connector
 *
 *  Receive option name and value to build the openvasd connector
 *
 *  @param conn struct holding the openvasd connector information
 *  @param opt    option to set
 *  @param val    value to set
 *
 *  @return Return OK on success, otherwise error;
 */
openvasd_error_t
openvasd_connector_builder (openvasd_connector_t conn, openvasd_conn_opt_t opt,
                            const void *val)
{
  if (conn == NULL)
    conn = openvasd_connector_new ();

  if (opt < OPENVASD_CA_CERT || opt > OPENVASD_PORT)
    return OPENVASD_INVALID_OPT;

  if (val == NULL)
    return OPENVASD_INVALID_VALUE;

  switch (opt)
    {
    case OPENVASD_CA_CERT:
      conn->ca_cert = g_strdup ((char *) val);
      break;
    case OPENVASD_CERT:
      conn->cert = g_strdup ((char *) val);
      break;
    case OPENVASD_KEY:
      conn->key = g_strdup ((char *) val);
      break;
    case OPENVASD_API_KEY:
      conn->apikey = g_strdup ((char *) val);
      break;
    case OPENVASD_SERVER:
      conn->server = g_strdup ((char *) val);
      break;
    case OPENVASD_HOST:
      conn->host = g_strdup ((char *) val);
      break;
    case OPENVASD_SCAN_ID:
      conn->scan_id = g_strdup ((const gchar *) val);
      break;
    case OPENVASD_PORT:
    default:
      conn->port = *((int *) val);
      break;
    };

  return OPENVASD_OK;
}

/** @brief Build a openvasd connector
 *
 *  Receive option name and value to build the openvasd connector
 *
 *  @param conn   struct holding the openvasd connector information
 *
 *  @return Return OPENVASD_OK
 */
openvasd_error_t
openvasd_connector_free (openvasd_connector_t conn)
{
  if (conn == NULL)
    return OPENVASD_OK;

  g_free (conn->ca_cert);
  g_free (conn->cert);
  g_free (conn->key);
  g_free (conn->apikey);
  g_free (conn->server);
  g_free (conn->host);
  g_free (conn->scan_id);
  gvm_http_response_stream_free (conn->stream_resp);
  g_free (conn);
  conn = NULL;

  return OPENVASD_OK;
}

/**
 * @brief Free an openvasd response struct
 *
 * @param resp Response to be freed
 */
void
openvasd_response_cleanup (openvasd_resp_t resp)
{
  if (resp == NULL)
    return;

  g_free (resp->body);
  g_free (resp->header);
  g_free (resp);
  resp = NULL;
}

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
 * @brief Sends an HTTP(S) request to the OpenVAS daemon using
 *        the specified parameters.
 *
 * @param conn The `openvasd_connector_t` containing server and certificate
 * details.
 * @param method The HTTP method (GET, POST, etc.).
 * @param path The resource path (e.g., `/vts`).
 * @param data The request payload (if applicable).
 * @param custom_headers Additional request headers.
 * @param header_name The header key to extract from the response.
 *
 * @return `openvasd_resp_t` containing response status, body, and header value.
 */
static openvasd_resp_t
openvasd_send_request (openvasd_connector_t conn,
                       gvm_http_method_t method, const gchar *path,
                       const gchar *data,
                       gvm_http_headers_t *custom_headers,
                       const gchar *header_name)
{
  openvasd_resp_t response = g_malloc0 (sizeof (struct openvasd_response));
  response->code = RESP_CODE_ERR;
  response->body = NULL;
  response->header = NULL;

  if (!conn)
    {
      g_warning ("openvasd_send_request_test: Invalid connector");
      response->body = g_strdup ("{\"error\": \"Missing openvasd connector\"}");
      return response;
    }

  gchar *url = g_strdup_printf ("%s:%d%s", conn->server, conn->port, path);

  if (!conn->stream_resp)
    {
      conn->stream_resp = g_malloc0 (sizeof (struct gvm_http_response_stream));
    }

  // Send request
  gvm_http_response_t *http_response = gvm_http_request (url, method,
                                                         data,
                                                         custom_headers,
                                                         conn->ca_cert,
                                                         conn->cert,
                                                         conn->key,
                                                         conn->stream_resp);

  // Check for request errors
  if (http_response->http_status == -1)
    {
      g_warning ("%s: Error performing CURL request", __func__);
      response->body = g_strdup ("{\"error\": \"Error sending request\"}");
      gvm_http_headers_free (custom_headers);
      gvm_http_response_cleanup (http_response);
      g_free (url);
      return response;
    }

  // Populate response struct
  response->code = (int) http_response->http_status;
  response->body = g_strdup (http_response->data ? http_response->data :
                             "{\"error\": \"No response\"}");

  // Extract specific header if requested
  if (header_name)
    {
      struct curl_header *hname;
      if (curl_easy_header (http_response->http->handler, header_name, 0,
                            CURLH_HEADER, -1, &hname) == CURLHE_OK)
        {
          response->header = g_strdup (hname->value);
        }
    }

  // Cleanup
  gvm_http_response_cleanup (http_response);
  g_free (url);

  return response;
}

/**
 * @brief Request HEAD
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return Response containing the header information
 */
openvasd_resp_t
openvasd_get_version (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  customheader = init_customheader (conn->apikey, FALSE);

  response = openvasd_send_request (conn, HEAD, "/", NULL,
                                    customheader, NULL);

  gvm_http_headers_free(customheader);
  openvasd_reset_vt_stream (conn);
  return response;
}

/**
 * @brief Initialized an curl multiperform handler which allows fetch feed
 * metadata chunk by chunk.
 *
 * @param conn Connector struct with the data necessary for the connection
 * @param mhnd The curl multiperform handler. It the caller doesn't provide
 * it initialized, it will be initialized. The caller has to free it with
 * gvm_http_multi_free().
 * @param resp The stringstream struct for the write callback function.
 *
 * @return The response.
 */
openvasd_resp_t
openvasd_get_vt_stream_init (openvasd_connector_t conn)
{
  GString *path;
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  response = g_malloc0 (sizeof (struct openvasd_response));

  path = g_string_new ("/vts?information=1");
  gchar *url = g_strdup_printf ("%s:%d%s", conn->server, conn->port, path->str);

  customheader = init_customheader (conn->apikey, FALSE);

  if (!conn->stream_resp) {
      conn->stream_resp = g_malloc0 (sizeof(struct gvm_http_response_stream));
  }

  gvm_http_multi_t *multi_handle = gvm_http_multi_new();
  if (!multi_handle)
    {
      g_warning ("%s: Failed to initialize curl multi-handle", __func__);
      g_string_free (path, TRUE);
      g_free (url);
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Failed to initialize multi-handle\"}");
      return response;
    }

  // Initialize request using curlutils
  gvm_http_t *http = gvm_http_new (
      url, GET, NULL, customheader,
      conn->ca_cert, conn->cert, conn->key, conn->stream_resp
  );

  g_string_free (path, TRUE);
  g_free(url);

  // Check if curl handle was created properly
  if (!http || !http->handler) {
      g_warning("%s: Failed to initialize curl request", __func__);
      gvm_http_headers_free (customheader);
      gvm_http_multi_free (multi_handle);
      response->code = RESP_CODE_ERR;
      response->body = g_strdup("{\"error\": \"Failed to initialize CURL request\"}");
      return response;
  }

  gvm_http_multi_result_t multi_add_result = gvm_http_multi_add_handler (multi_handle, http);
  if (multi_add_result != GVM_HTTP_OK) {
      g_warning("%s: Failed to add CURL handle to multi", __func__);
      gvm_http_multi_handler_free (multi_handle, http);
      gvm_http_headers_free (customheader);
      gvm_http_multi_free (multi_handle);
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Failed to add CURL handle to multi\"}");
      return response;
  }

  conn->stream_resp->multi_handler = multi_handle;
  conn->stream_resp->multi_handler->headers = customheader;

  g_debug("%s: Multi handle initialized successfully", __func__);

  response->code = RESP_CODE_OK;
  return response;
}

void
openvasd_reset_vt_stream (openvasd_connector_t conn)
{
  gvm_http_response_stream_reset (conn->stream_resp);
}

gchar *
openvasd_vt_stream_str (openvasd_connector_t conn)
{
  return conn->stream_resp->data;
}

size_t
openvasd_vt_stream_len (openvasd_connector_t conn)
{
  return conn->stream_resp->length;
}

/**
 * @brief Get a new feed metadata chunk.
 *
 * This function must be call until the
 * return value is 0, meaning there is no more data to fetch.
 *
 * @param mhnd Curl multiperfom for requesting the feed metadata
 *
 * @return greather than 0 if the handler is still getting data. 0 if the
 * transmision finished. -1 on error
 */
int
openvasd_get_vt_stream (openvasd_connector_t conn)
{
  static int running = 0;

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
      CURLMcode poll_result = curl_multi_poll (multi->handler, NULL, 0, 5000, NULL);
      if (poll_result != CURLM_OK)
        {
          g_warning ("%s: error on curl_multi_poll(): %d\n", __func__, poll_result);
          return -1;
        }
    }

  return running;
}

/**
 * @brief Get VT's metadata
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return Response Struct containing the feed metadata in json format in the
 * body.
 */
openvasd_resp_t
openvasd_get_vts (openvasd_connector_t conn)
{
  GString *path;
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  path = g_string_new ("/vts?information=1");
  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, path->str, NULL,
                                    customheader, NULL);

  g_string_free (path, TRUE);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));

  openvasd_reset_vt_stream (conn);
  return response;
}

/**
 * @Brief Get VT's metadata
 *
 * @param conn Connector struct with the data necessary for the connection
 * @param data String containing the scan config in JSON format.
 *
 * @return Response Struct containing the resonse.
 */
openvasd_resp_t
openvasd_start_scan (openvasd_connector_t conn, gchar *data)
{
  openvasd_resp_t response = NULL;
  cJSON *parser = NULL;
  GString *path;
  gvm_http_headers_t *customheader = NULL;

  customheader = init_customheader (conn->apikey, TRUE);
  response = openvasd_send_request (conn, POST, "/scans", data,
                                    customheader, NULL);

  gvm_http_headers_free (customheader);

  if (response->code == RESP_CODE_ERR)
    {
      response->code = RESP_CODE_ERR;
      if (response->body == NULL)
        response->body =
          g_strdup ("{\"error\": \"Storing scan configuration\"}");
      g_warning ("%s: Error storing scan configuration ", __func__);
      openvasd_reset_vt_stream (conn);
      return response;
    }

  // Get the Scan ID
  parser = cJSON_Parse (openvasd_vt_stream_str (conn));
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
      openvasd_reset_vt_stream (conn);
      return response;
    }

  conn->scan_id = g_strdup (cJSON_GetStringValue (parser));

  // Start the scan
  path = g_string_new ("/scans");
  if (conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
    }
  else
    {
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      cJSON_Delete (parser);
      return response;
    }

  openvasd_reset_vt_stream (conn);
  customheader = init_customheader (conn->apikey, TRUE);
  response = openvasd_send_request (conn, POST, path->str,
                               "{\"action\": \"start\"}", customheader,NULL);

  g_string_free (path, TRUE);

  gvm_http_headers_free (customheader);
  if (response->code == RESP_CODE_ERR)
    {
      response->code = RESP_CODE_ERR;
      if (response->body == NULL)
        response->body = g_strdup ("{\"error\": \"Starting the scan.\"}");
      g_warning ("%s: Error starting the scan.", __func__);
      return response;
    }

  cJSON_Delete (parser);
  response->body = g_strdup (openvasd_vt_stream_str (conn));
  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_resp_t
openvasd_stop_scan (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  GString *path;
  gvm_http_headers_t *customheader = NULL;

  // Stop the scan
  path = g_string_new ("/scans");
  if (conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
    }
  else
    {
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  customheader = init_customheader (conn->apikey, TRUE);
  response = openvasd_send_request (conn, POST, path->str,
                               "{\"action\": \"stop\"}",
                                    customheader, NULL);

  g_string_free (path, TRUE);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));

  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_resp_t
openvasd_get_scan_results (openvasd_connector_t conn, long first, long last)
{
  openvasd_resp_t response = NULL;
  GString *path = NULL;
  gvm_http_headers_t *customheader = NULL;

  response = g_malloc0 (sizeof (struct openvasd_response));

  path = g_string_new ("/scans");
  if (conn->scan_id != NULL && conn->scan_id[0] != '\0')
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
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, path->str,
                               NULL, customheader, NULL);
  g_string_free (path, TRUE);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      g_warning ("%s: Not possible to get scan results", __func__);
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan results\"}");
    }

  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_result_t
openvasd_result_new (unsigned long id, gchar *type, gchar *ip_address,
                     gchar *hostname, gchar *oid, int port, gchar *protocol,
                     gchar *message, gchar *detail_name, gchar *detail_value,
                     gchar *detail_source_type, gchar *detail_source_name,
                     gchar *detail_source_description)
{
  openvasd_result_t result = g_malloc0 (sizeof (struct openvasd_result));

  result->id = id;
  result->type = g_strdup (type);
  result->ip_address = g_strdup (ip_address);
  result->hostname = g_strdup (hostname);
  result->oid = g_strdup (oid);
  result->port = port;
  result->protocol = g_strdup (protocol);
  result->message = g_strdup (message);
  result->detail_name = g_strdup (detail_name);
  result->detail_value = g_strdup (detail_value);
  result->detail_source_name = g_strdup (detail_source_name);
  result->detail_source_type = g_strdup (detail_source_type);
  result->detail_source_description = g_strdup (detail_source_description);

  return result;
}

char *
openvasd_get_result_member_str (openvasd_result_t result,
                                openvasd_result_member_string_t member)
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
    case PROTOCOL:
      return result->protocol;
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

int
openvasd_get_result_member_int (openvasd_result_t result,
                                openvasd_result_member_int_t member)
{
  if (!result)
    return -1;

  switch (member)
    {
    case ID:
      return result->id;
    case PORT:
      return result->port;
    default:
      return -1;
    }
}

void
openvasd_result_free (openvasd_result_t result)
{
  if (result == NULL)
    return;

  g_free (result->type);
  g_free (result->ip_address);
  g_free (result->hostname);
  g_free (result->oid);
  g_free (result->protocol);
  g_free (result->message);
  g_free (result->detail_name);
  g_free (result->detail_value);
  g_free (result->detail_source_name);
  g_free (result->detail_source_type);
  g_free (result->detail_source_description);
  g_free (result);
  result = NULL;
}

static int
parse_results (const gchar *body, GSList **results)
{
  cJSON *parser;
  cJSON *result_obj = NULL;
  const gchar *err = NULL;
  openvasd_result_t result = NULL;
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
    gchar *detail_name = NULL;
    gchar *detail_value = NULL;
    gchar *detail_source_type = NULL;
    gchar *detail_source_name = NULL;
    gchar *detail_source_description = NULL;

    if (!cJSON_IsObject (result_obj))
      // error
      goto res_cleanup;

    item = cJSON_GetObjectItem (result_obj, "detail");
    if (item != NULL
        && cJSON_IsObject (item))
      {
        cJSON *detail_obj = NULL;

        detail_name = gvm_json_obj_str (item, "name");
        detail_value = gvm_json_obj_str (item, "value");

        detail_obj = cJSON_GetObjectItem (item, "source");
        if (detail_obj && cJSON_IsObject (detail_obj))
          {
            detail_source_type = gvm_json_obj_str (detail_obj, "type");
            detail_source_name = gvm_json_obj_str (detail_obj, "name");
            detail_source_description = gvm_json_obj_str (detail_obj, "description");
          }
      }

    result = openvasd_result_new (gvm_json_obj_double (result_obj, "id"),
                                  gvm_json_obj_str (result_obj, "type"),
                                  gvm_json_obj_str (result_obj, "ip_address"),
                                  gvm_json_obj_str (result_obj, "hostname"),
                                  gvm_json_obj_str (result_obj, "oid"),
                                  gvm_json_obj_int (result_obj, "port"),
                                  gvm_json_obj_str (result_obj, "protocol"),
                                  gvm_json_obj_str (result_obj, "message"),
                                  detail_name, detail_value,
                                  detail_source_type, detail_source_name,
                                  detail_source_description);

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

int
openvasd_parsed_results (openvasd_connector_t conn, unsigned long first,
                         unsigned long last, GSList **results)
{
  int ret;
  openvasd_resp_t resp;

  resp = openvasd_get_scan_results (conn, first, last);
  if (resp->code == 200)
    ret = parse_results (resp->body, results);
  else
    ret = resp->code;

  openvasd_response_cleanup (resp);

  return ret;
}

openvasd_resp_t
openvasd_get_scan_status (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  GString *path = NULL;
  gvm_http_headers_t *customheader = NULL;

  path = g_string_new ("/scans");
  if (conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
      g_string_append (path, "/status");
    }
  else
    {
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, path->str,
                                    NULL, customheader, NULL);
  g_string_free (path, TRUE);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan status\"}");
      g_warning ("%s: Not possible to get scan status", __func__);
    }

  openvasd_reset_vt_stream (conn);
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

static int
openvasd_get_scan_progress_ext (openvasd_connector_t conn,
                                openvasd_resp_t response)
{
  cJSON *parser;
  cJSON *reader = NULL;
  const gchar *err = NULL;
  int all = 0, excluded = 0, dead = 0, alive = 0, queued = 0, finished = 0;
  int running_hosts_progress_sum = 0;

  openvasd_resp_t resp;
  int progress = -1;

  if (!response && !conn)
    return -1;

  if (response == NULL)
    resp = openvasd_get_scan_status (conn);
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
  if (scanning != NULL
      && cJSON_IsObject (scanning))
    {
      cJSON *host = scanning->child;
      while (host)
        {
          running_hosts_progress_sum += cJSON_GetNumberValue (host);
          host = host->next;
        }

    } // end scanning
  // end host_info

  if (all < 0 || excluded < 0 || dead < 0 || alive < 0 || queued < 0
      || finished < 0)
    {
      goto cleanup;
    }

  if ((all + finished - dead) > 0)
    progress = (running_hosts_progress_sum + 100 * (alive + finished))
               / (all + finished - dead);
  else
    progress = 100;

cleanup:
  if (err != NULL)
    g_warning ("%s: Unable to parse scan status. Reason: %s", __func__, err);
  cJSON_Delete (parser);

  return progress;
}

int
openvasd_get_scan_progress (openvasd_connector_t conn)
{
  return openvasd_get_scan_progress_ext (conn, NULL);
}

static openvasd_status_t
get_status_code_from_openvas (const gchar *status_val)
{
  openvasd_status_t status_code = OPENVASD_SCAN_STATUS_ERROR;

  if (g_strcmp0 (status_val, "stored") == 0)
    status_code = OPENVASD_SCAN_STATUS_STORED;
  else if (g_strcmp0 (status_val, "requested") == 0)
    status_code = OPENVASD_SCAN_STATUS_REQUESTED;
  else if (g_strcmp0 (status_val, "running") == 0)
    status_code = OPENVASD_SCAN_STATUS_RUNNING;
  else if (g_strcmp0 (status_val, "stopped") == 0)
    status_code = OPENVASD_SCAN_STATUS_STOPPED;
  else if (g_strcmp0 (status_val, "succeeded") == 0)
    status_code = OPENVASD_SCAN_STATUS_SUCCEEDED;
  else if (g_strcmp0 (status_val, "interrupted") == 0)
    status_code = OPENVASD_SCAN_STATUS_FAILED;

  return status_code;
}

static int
parse_status (const gchar *body, openvasd_scan_status_t status_info)
{
  cJSON *parser;
  gchar *status_val = NULL;
  openvasd_status_t status_code = OPENVASD_SCAN_STATUS_ERROR;

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

  status_code = get_status_code_from_openvas (status_val);

  status_info->status = status_code;
  status_info->end_time = gvm_json_obj_double (parser, "end_time");
  status_info->start_time = gvm_json_obj_double (parser, "start_time");
  cJSON_Delete (parser);

  return 0;
}

/** @brief Return a struct with the general scan status
 *
 *  @param conn openvasd connector data
 *
 *  @return The data in a struct. The struct must be freed
 *          by the caller.
 */
openvasd_scan_status_t
openvasd_parsed_scan_status (openvasd_connector_t conn)
{
  openvasd_resp_t resp = NULL;
  int progress = -1;
  openvasd_status_t status_code = OPENVASD_SCAN_STATUS_ERROR;
  openvasd_scan_status_t status_info = NULL;

  resp = openvasd_get_scan_status (conn);

  status_info = g_malloc0 (sizeof (struct openvasd_scan_status));
  if (resp->code != 200 || parse_status (resp->body, status_info) == -1)
    {
      status_info->status = status_code;
      status_info->response_code = resp->code;
      openvasd_response_cleanup (resp);
      return status_info;
    }

  progress = openvasd_get_scan_progress_ext (NULL, resp);
  openvasd_response_cleanup (resp);
  status_info->progress = progress;

  return status_info;
}

openvasd_resp_t
openvasd_delete_scan (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  GString *path;
  gvm_http_headers_t *customheader = NULL;

  // Stop the scan
  path = g_string_new ("/scans");
  if (conn->scan_id != NULL && conn->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, conn->scan_id);
    }
  else
    {
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, DELETE, path->str,
                                    NULL, customheader, NULL);

  g_string_free (path, TRUE);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to delete scan.\"}");
      g_warning ("%s: Not possible to delete scan", __func__);
    }

  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_resp_t
openvasd_get_health_alive (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, "/health/alive",
                                         NULL, customheader, NULL);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_resp_t
openvasd_get_health_ready (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, "/health/ready",
                                         NULL, customheader, "feed-version");

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_resp_t
openvasd_get_health_started (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, "/health/started",
                                         NULL, customheader, NULL);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  openvasd_reset_vt_stream (conn);
  return response;
}

openvasd_resp_t
openvasd_get_scan_preferences (openvasd_connector_t conn)
{
  openvasd_resp_t response = NULL;
  gvm_http_headers_t *customheader = NULL;

  customheader = init_customheader (conn->apikey, FALSE);
  response = openvasd_send_request (conn, GET, "/scans/preferences",
                                         NULL, customheader, NULL);

  gvm_http_headers_free (customheader);
  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (openvasd_vt_stream_str (conn));
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scans preferences.\"}");
      g_warning ("%s: Not possible to get scans_preferences", __func__);
    }

  openvasd_reset_vt_stream (conn);
  return response;
}

/**
 * @brief Create a new openvasd parameter.
 *
 * @return New openvasd parameter.
 */
static openvasd_param_t *
openvasd_param_new (char *id, gchar *name, gchar *defval, gchar *description,
                    gchar *type, int mandatory)
{
  openvasd_param_t *param = g_malloc0 (sizeof (openvasd_param_t));

  param->id = id;
  param->defval = defval;
  param->description = description;
  param->name = name;
  param->mandatory = mandatory;
  param->type = type;
  return param;
}

/**
 * @brief Free an openvasd parameter.
 *
 * @param param openvasd parameter to destroy.
 */
void
openvasd_param_free (openvasd_param_t *param)
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
 * @brief Get the parameter id
 *
 * @param param openvasd parameter
 */
char *
openvasd_param_id (openvasd_param_t *param)
{
  if (!param)
    return NULL;

  return param->id;
}

/**
 * @brief Get the parameter default
 *
 * @param param openvasd parameter
 */
char *
openvasd_param_name (openvasd_param_t *param)
{
  if (!param)
    return NULL;

  return param->defval;
}

/**
 * @brief Get the parameter description
 *
 * @param param openvasd parameter
 */
char *
openvasd_param_desc (openvasd_param_t *param)
{
  if (!param)
    return NULL;

  return param->description;
}

/**
 * @brief Get the parameter type
 *
 * @param param openvasd parameter
 */
char *
openvasd_param_type (openvasd_param_t *param)
{
  if (!param)
    return NULL;

  return param->type;
}

/**
 * @brief Get the parameter default
 *
 * @param param openvasd parameter
 */
char *
openvasd_param_default (openvasd_param_t *param)
{
  if (!param)
    return NULL;

  return param->defval;
}

/**
 * @brief If the parameter is mandatory
 *
 * @param param openvasd parameter
 */
int
openvasd_param_mandatory (openvasd_param_t *param)
{
  if (!param)
    return 0;

  return param->mandatory;
}

int
openvasd_parsed_scans_preferences (openvasd_connector_t conn, GSList **params)
{
  openvasd_resp_t resp = NULL;
  cJSON *parser;
  cJSON *param_obj = NULL;
  int err = 0;

  resp = openvasd_get_scan_preferences (conn);

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
    openvasd_param_t *param = NULL;
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

    param =
      openvasd_param_new (g_strdup (gvm_json_obj_str (param_obj, "id")),
                          g_strdup (gvm_json_obj_str (param_obj, "name")),
                          g_strdup (defval),
                          g_strdup (gvm_json_obj_str (param_obj, "description")),
                          g_strdup (param_type), mandatory);
    g_free (defval);
    g_free (param_type);
    *params = g_slist_append (*params, param);
  }

prefs_cleanup:
  openvasd_response_cleanup (resp);
  cJSON_Delete (parser);
  if (err)
    {
      g_warning ("%s: Unable to parse scan preferences.", __func__);
      return -1;
    }

  return 0;
}

// Scan config builder
static void
add_port_to_scan_json (gpointer range, gpointer p_array)
{
  range_t *ports = range;

  cJSON *port = cJSON_CreateObject ();
  if (ports->type == 1)
    cJSON_AddStringToObject (port, "protocol", "udp");
  else
    cJSON_AddStringToObject (port, "protocol", "tcp");

  cJSON *ranges_array = cJSON_CreateArray ();
  cJSON *range_obj = cJSON_CreateObject ();
  cJSON_AddNumberToObject (range_obj, "start", ports->start);

  if (ports->end > ports->start && ports->end < 65535)
    cJSON_AddNumberToObject (range_obj, "end", ports->end);
  else
    cJSON_AddNumberToObject (range_obj, "end", ports->start);
  cJSON_AddItemToArray (ranges_array, range_obj);
  cJSON_AddItemToObject (port, "range", ranges_array);
  cJSON_AddItemToArray ((cJSON *) p_array, port);
}

static void
add_credential_to_scan_json (gpointer credentials, gpointer cred_array)
{
  GHashTableIter auth_data_iter;
  gchar *auth_data_name, *auth_data_value;
  cJSON *cred_obj = NULL;

  openvasd_credential_t *cred = credentials;

  cred_obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (cred_obj, "service", cred->service);

  if (cred->port)
    {
      cJSON_AddNumberToObject (cred_obj, "port", atoi (cred->port));
    }

  cJSON *cred_type_obj = cJSON_CreateObject ();
  g_hash_table_iter_init (&auth_data_iter, cred->auth_data);
  while (g_hash_table_iter_next (&auth_data_iter, (gpointer *) &auth_data_name,
                                 (gpointer *) &auth_data_value))
    cJSON_AddStringToObject (cred_type_obj, auth_data_name, auth_data_value);
  cJSON_AddItemToObject (cred_obj, cred->type, cred_type_obj);

  cJSON_AddItemToArray ((cJSON *) cred_array, cred_obj);
}

static void
add_scan_preferences_to_scan_json (gpointer key, gpointer val,
                                   gpointer scan_prefs_array)
{
  cJSON *pref_obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (pref_obj, "id", key);
  cJSON_AddStringToObject (pref_obj, "value", val);
  cJSON_AddItemToArray (scan_prefs_array, pref_obj);
}

static void
add_vts_to_scan_json (gpointer single_vt, gpointer vts_array)
{
  GHashTableIter vt_data_iter;
  gchar *vt_param_id, *vt_param_value;

  openvasd_vt_single_t *vt = single_vt;

  cJSON *vt_obj = cJSON_CreateObject ();

  cJSON_AddStringToObject (vt_obj, "oid", vt->vt_id);

  if (g_hash_table_size (vt->vt_values))
    {
      cJSON *params_array = cJSON_CreateArray ();

      g_hash_table_iter_init (&vt_data_iter, vt->vt_values);
      while (g_hash_table_iter_next (&vt_data_iter, (gpointer *) &vt_param_id,
                                     (gpointer *) &vt_param_value))
        {
          cJSON *param_obj = cJSON_CreateObject ();
          cJSON_AddNumberToObject (param_obj, "id", atoi (vt_param_id));
          cJSON_AddStringToObject (param_obj, "value", vt_param_value);
          cJSON_AddItemToArray (params_array, param_obj);
        }
      cJSON_AddItemToObject (vt_obj, "parameters", params_array);
    }
  cJSON_AddItemToArray (vts_array, vt_obj);
}

/**
 * @brief Build a json object with data necessary to start a scan
 *
 * JSON result consists of scan_id, message type, host ip,
 * hostname, port, together with proto, OID, result message and uri.
 *
 * @param target      target
 * @param scan_preferences Scan preferences to be added to the scan config
 * @param vts VTS collection to be added to the scan config.
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
char *
openvasd_build_scan_config_json (openvasd_target_t *target,
                                 GHashTable *scan_preferences, GSList *vts)
{
  cJSON *scan_obj = NULL;
  cJSON *target_obj = NULL;
  cJSON *hosts_array = NULL;
  cJSON *exclude_hosts_array = NULL;
  cJSON *finished_hosts_array = NULL;
  gchar *json_str = NULL;

  /* Build the message in json format to be published. */
  scan_obj = cJSON_CreateObject ();

  if (target->scan_id && target->scan_id[0] != '\0')
    cJSON_AddStringToObject (scan_obj, "scan_id", target->scan_id);

  // begin target
  target_obj = cJSON_CreateObject ();

  // hosts
  hosts_array = cJSON_CreateArray ();
  gchar **hosts_list = g_strsplit (target->hosts, ",", 0);
  for (int i = 0; hosts_list[i] != NULL; i++)
    {
      cJSON *host_item = NULL;
      host_item = cJSON_CreateString (hosts_list[i]);
      cJSON_AddItemToArray (hosts_array, host_item);
    }
  g_strfreev (hosts_list);
  cJSON_AddItemToObject (target_obj, "hosts", hosts_array);

  // exclude hosts
  if (target->exclude_hosts && target->exclude_hosts[0] != '\0')
    {
      exclude_hosts_array = cJSON_CreateArray ();
      gchar **exclude_hosts_list = g_strsplit (target->exclude_hosts, ",", 0);
      for (int i = 0; exclude_hosts_list[i] != NULL; i++)
        {
          cJSON *exclude_host_item = NULL;
          exclude_host_item = cJSON_CreateString (exclude_hosts_list[i]);
          cJSON_AddItemToArray (exclude_hosts_array, exclude_host_item);
        }
      g_strfreev (exclude_hosts_list);
      cJSON_AddItemToObject (target_obj, "excluded_hosts", exclude_hosts_array);
    }

  // finished hosts
  if (target->finished_hosts && target->finished_hosts[0] != '\0')
    {
      finished_hosts_array = cJSON_CreateArray ();
      gchar **finished_hosts_list = g_strsplit (target->finished_hosts, ",", 0);
      for (int i = 0; finished_hosts_list[i] != NULL; i++)
        {
          cJSON *finished_host_item = NULL;
          finished_host_item = cJSON_CreateString (finished_hosts_list[i]);
          cJSON_AddItemToArray (finished_hosts_array, finished_host_item);
        }
      g_strfreev (hosts_list);
      cJSON_AddItemToObject (target_obj, "finished_hosts",
                             finished_hosts_array);
    }

  // ports
  if (target->ports && target->ports[0] != '\0')
    {
      cJSON *ports_array = cJSON_CreateArray ();
      array_t *ports = port_range_ranges (target->ports);
      g_ptr_array_foreach (ports, add_port_to_scan_json, ports_array);
      array_free (ports);
      cJSON_AddItemToObject (target_obj, "ports", ports_array);
    }

  // credentials
  cJSON *credentials = cJSON_CreateArray ();
  g_slist_foreach (target->credentials, add_credential_to_scan_json,
                   credentials);
  cJSON_AddItemToObject (target_obj, "credentials", credentials);

  // reverse lookup
  if (target->reverse_lookup_unify)
    cJSON_AddBoolToObject (target_obj, "reverse_lookup_unify", cJSON_True);
  else
    cJSON_AddBoolToObject (target_obj, "reverse_lookup_unify", cJSON_False);

  if (target->reverse_lookup_only)
    cJSON_AddBoolToObject (target_obj, "reverse_lookup_only", cJSON_True);
  else
    cJSON_AddBoolToObject (target_obj, "reverse_lookup_only", cJSON_False);

  // alive test methods
  cJSON *alive_test_methods = cJSON_CreateArray ();
  if (target->arp)
    cJSON_AddItemToArray (alive_test_methods, cJSON_CreateString ("arp"));
  if (target->tcp_ack)
    cJSON_AddItemToArray (alive_test_methods, cJSON_CreateString ("tcp_ack"));
  if (target->tcp_syn)
    cJSON_AddItemToArray (alive_test_methods, cJSON_CreateString ("tcp_syn"));
  if (target->consider_alive)
    cJSON_AddItemToArray (alive_test_methods,
                          cJSON_CreateString ("consider_alive"));
  if (target->icmp)
    cJSON_AddItemToArray (alive_test_methods, cJSON_CreateString ("icmp"));
  cJSON_AddItemToObject (target_obj, "alive_test_methods", alive_test_methods);

  cJSON_AddItemToObject (scan_obj, "target", target_obj);

  // Begin Scan Preferences
  cJSON *scan_prefs_array = cJSON_CreateArray ();
  g_hash_table_foreach (scan_preferences, add_scan_preferences_to_scan_json,
                        scan_prefs_array);
  cJSON_AddItemToObject (scan_obj, "scan_preferences", scan_prefs_array);

  // Begin VTs
  cJSON *vts_array = cJSON_CreateArray ();
  g_slist_foreach (vts, add_vts_to_scan_json, vts_array);
  cJSON_AddItemToObject (scan_obj, "vts", vts_array);

  json_str = cJSON_Print (scan_obj);
  cJSON_Delete (scan_obj);
  if (json_str == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);

  return json_str;
}

/**
 * @brief Allocate and initialize a new openvasd credential.
 *
 * @param type      The credential type.
 * @param service   The service the credential is for.
 * @param port      The port.
 *
 * @return New openvasd credential.
 */
openvasd_credential_t *
openvasd_credential_new (const gchar *type, const gchar *service,
                         const gchar *port)
{
  openvasd_credential_t *new_credential;

  new_credential = g_malloc0 (sizeof (openvasd_credential_t));

  new_credential->type = type ? g_strdup (type) : NULL;
  new_credential->service = service ? g_strdup (service) : NULL;
  new_credential->port = port ? g_strdup (port) : NULL;
  new_credential->auth_data =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_credential;
}

/**
 * @brief Free an openvasd credential.
 *
 * @param credential  The credential to free.
 */
void
openvasd_credential_free (openvasd_credential_t *credential)
{
  if (!credential)
    return;

  g_free (credential->type);
  g_free (credential->service);
  g_free (credential->port);
  g_hash_table_destroy (credential->auth_data);
  g_free (credential);
}

/**
 * @brief Get authentication data from an openvasd credential.
 *
 * @param  credential  The credential to get the data from.
 * @param  name        The name of the data item to get.
 * @param  value       The authentication data or NULL to unset.
 */
void
openvasd_credential_set_auth_data (openvasd_credential_t *credential,
                                   const gchar *name, const gchar *value)
{
  if (credential == NULL || name == NULL)
    return;

  if (g_regex_match_simple ("^[[:alpha:]][[:alnum:]_]*$", name, 0, 0))
    {
      if (value)
        g_hash_table_replace (credential->auth_data, g_strdup (name),
                              g_strdup (value));
      else
        g_hash_table_remove (credential->auth_data, name);
    }
  else
    {
      g_warning ("%s: Invalid auth data name: %s", __func__, name);
    }
}

/**
 * @brief Create a new openvasd target.
 *
 * @param scanid         Scan ID.
 * @param hosts          The hostnames of the target.
 * @param ports          The ports of the target.
 * @param exclude_hosts  The excluded hosts of the target.
 * @param reverse_lookup_unify  Lookup flag.
 * @param reverse_lookup_only   Lookup flag.
 *
 * @return The newly allocated openvasd_target_t.
 */
openvasd_target_t *
openvasd_target_new (const gchar *scanid, const gchar *hosts,
                     const gchar *ports, const gchar *exclude_hosts,
                     int reverse_lookup_unify, int reverse_lookup_only)
{
  openvasd_target_t *new_target;
  new_target = g_malloc0 (sizeof (openvasd_target_t));

  if (scanid && *scanid)
    new_target->scan_id = g_strdup (scanid);

  new_target->exclude_hosts = exclude_hosts ? g_strdup (exclude_hosts) : NULL;
  new_target->finished_hosts = NULL;
  new_target->hosts = hosts ? g_strdup (hosts) : NULL;
  new_target->ports = ports ? g_strdup (ports) : NULL;
  new_target->reverse_lookup_unify =
    reverse_lookup_unify ? reverse_lookup_unify : 0;
  new_target->reverse_lookup_only =
    reverse_lookup_only ? reverse_lookup_only : 0;

  return new_target;
}

/**
 * @brief Set the finished hosts of an openvasd target.
 *
 * @param target         The openvasd target to modify.
 * @param finished_hosts The hostnames to consider finished.
 */
void
openvasd_target_set_finished_hosts (openvasd_target_t *target,
                                    const gchar *finished_hosts)
{
  g_free (target->finished_hosts);
  target->finished_hosts = finished_hosts ? g_strdup (finished_hosts) : NULL;
}

/**
 * @brief Free an openvasd target, including all added credentials.
 *
 * @param target  The openvasd target to free.
 */
void
openvasd_target_free (openvasd_target_t *target)
{
  if (!target)
    return;

  g_slist_free_full (target->credentials,
                     (GDestroyNotify) openvasd_credential_free);
  g_free (target->exclude_hosts);
  g_free (target->finished_hosts);
  g_free (target->scan_id);
  g_free (target->hosts);
  g_free (target->ports);
  g_free (target);
  target = NULL;
}

/**
 * @brief Add alive test methods to openvasd target.
 *
 * @param target           The openvasd target to add the methods to.
 * @param icmp             Use ICMP ping.
 * @param tcp_syn          Use TCP-SYN ping.
 * @param tcp_ack          Use TCP-ACK ping.
 * @param arp              Use ARP ping.
 * @param consider_alive   Consider host to be alive.
 */
void
openvasd_target_add_alive_test_methods (openvasd_target_t *target,
                                        gboolean icmp, gboolean tcp_syn,
                                        gboolean tcp_ack, gboolean arp,
                                        gboolean consider_alive)
{
  if (!target)
    return;

  target->icmp = icmp;
  target->tcp_syn = tcp_syn;
  target->tcp_ack = tcp_ack;
  target->arp = arp;
  target->consider_alive = consider_alive;
}

/**
 * @brief Add a credential to an openvasd target.
 *
 * @param target       The openvasd target to add the credential to.
 * @param credential   The credential to add. Will be freed with target.
 */
void
openvasd_target_add_credential (openvasd_target_t *target,
                                openvasd_credential_t *credential)
{
  if (!target || !credential)
    return;

  target->credentials = g_slist_prepend (target->credentials, credential);
}

/**
 * @brief Create a new single openvasd VT.
 *
 * @param vt_id  The id of the VT.
 *
 * @return  The newly allocated single VT.
 */
openvasd_vt_single_t *
openvasd_vt_single_new (const gchar *vt_id)
{
  openvasd_vt_single_t *new_vt_single;
  new_vt_single = g_malloc0 (sizeof (openvasd_vt_single_t));

  new_vt_single->vt_id = vt_id ? g_strdup (vt_id) : NULL;
  new_vt_single->vt_values =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_vt_single;
}

/**
 * @brief Free a single openvasd VT, including all preference values.
 *
 * @param vt_single  The openvasd VT to free.
 */
void
openvasd_vt_single_free (openvasd_vt_single_t *vt_single)
{
  if (!vt_single)
    return;

  g_hash_table_destroy (vt_single->vt_values);

  g_free (vt_single->vt_id);
  g_free (vt_single);
}

/**
 * @brief Add a preference value to an openvasd VT.
 *
 * This creates a copy of the name and value.
 *
 * @param vt_single  The VT to add the preference to.
 * @param name       The name / identifier of the preference.
 * @param value      The value of the preference.
 */
void
openvasd_vt_single_add_value (openvasd_vt_single_t *vt_single,
                              const gchar *name, const gchar *value)
{
  g_hash_table_replace (vt_single->vt_values, g_strdup (name),
                        g_strdup (value));
}
