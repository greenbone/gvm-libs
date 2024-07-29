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

#include <curl/curl.h>
#include <json-glib/json-glib.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm ovd"

#define RESP_CODE_ERR -1

struct openvasd_connector
{
  char *ca_cert; // Path to the directory holding the CA certificate
  char *cert;    // Client certificate
  char *key;     // Client key
  char *apikey;  // API key for authentication
  char *server;  // original openvasd server URL
  char *host;    // server hostname
  char *scan_id; // Scan ID
  int port;      // server port
};

/**
 * @brief Struct holding options for Openvasd parameters.
 */
struct openvasd_param
{
  char *id;    /**< Parameter id. */
  char *value; /**< Parameter name. */
};

/**
 * @brief Struct credential information for Openvasd.
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

enum openvas_request_method
{
  POST,
  GET,
  HEAD,
  DELETE,
};

typedef enum openvas_request_method openvasd_req_method_t;

/** @brief Initialize a notus info struct and stores the server URL
 *
 *  @param server Original server to store and to get the info from
 *
 *  @return the initialized struct. NULL on error.
 */
openvasd_connector_t
openvasd_connector_new (void)
{
  openvasd_connector_t connector;
  connector = g_malloc0 (sizeof (struct openvasd_connector));
  if (!connector)
    return NULL;

  return connector;
}

/** @brief Build a openvasd connector
 *  @Description Recieve option name and value to build the openvasd connector
 *
 *  @param[in/out] conn   struct holding the openvasd connector information
 *  @param[in] opt    option to set
 *  @param[in] val    value to set
 *
 *  @return Return OK on success, otherwise error;
 */
openvasd_error_t
openvasd_connector_builder (openvasd_connector_t *conn, openvasd_conn_opt_t opt,
                            const void *val)
{
  if (conn == NULL)
    *conn = openvasd_connector_new ();

  if (conn == NULL)
    return OPENVASD_NOT_INITIALIZED;

  if (opt < OPENVASD_CA_CERT || opt > OPENVASD_PORT)
    return OPENVASD_INVALID_OPT;

  if (val == NULL)
    return OPENVASD_INVALID_VALUE;

  switch (opt)
    {
    case OPENVASD_CA_CERT:
      (*conn)->ca_cert = g_strdup ((char *) val);
      break;
    case OPENVASD_CERT:
      (*conn)->cert = g_strdup ((char *) val);
      break;
    case OPENVASD_KEY:
      (*conn)->key = g_strdup ((char *) val);
      break;
    case OPENVASD_API_KEY:
      (*conn)->apikey = g_strdup ((char *) val);
      break;
    case OPENVASD_SERVER:
      (*conn)->server = g_strdup ((char *) val);
      break;
    case OPENVASD_HOST:
      (*conn)->host = g_strdup ((char *) val);
      break;
    case OPENVASD_SCAN_ID:
      (*conn)->scan_id = g_strdup ((const char *) val);
      break;
    case OPENVASD_PORT:
    default:
      (*conn)->port = *((int *) val);
      break;
    };

  return OPENVASD_OK;
}

/** @brief Build a openvasd connector
 *  @Description Recieve option name and value to build the openvasd connector
 *
 *  @param[in/out] conn   struct holding the openvasd connector information
 *  @param[in] opt    option to set
 *  @param[in] val    value to set
 *
 *  @return Return OK on success, otherwise error;
 */
openvasd_error_t
openvasd_connector_free (openvasd_connector_t *conn)
{
  if (*conn == NULL)
    return OPENVASD_OK;

  g_free ((*conn)->ca_cert);
  g_free ((*conn)->cert);
  g_free ((*conn)->key);
  g_free ((*conn)->server);
  g_free ((*conn)->host);
  g_free ((*conn)->scan_id);
  g_free (*conn);
  *conn = NULL;

  return OPENVASD_OK;
}

void
openvasd_response_free (openvasd_resp_t resp)
{
  if (resp == NULL)
    return;

  g_free (resp->body);
  g_free (resp->header);
  g_free (resp);
  resp = NULL;
}

/** @brief Define a string struct for storing the response.
 */
struct string
{
  char *ptr;
  size_t len;
};

/** @brief Initialize the string struct to hold the response
 *
 *  @param s[in/out] The string struct to be initialized
 */
static void
init_string (struct string *s)
{
  s->len = 0;
  s->ptr = g_malloc0 (s->len + 1);
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return;
    }
  s->ptr[0] = '\0';
}

/** @brief Call back function to stored the response.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the response in s. It reallocate memory if necessary.
 */
static size_t
response_callback_fn (void *ptr, size_t size, size_t nmemb, void *struct_string)
{
  struct string *s = struct_string;
  size_t new_len = s->len + size * nmemb;
  char *ptr_aux = g_realloc (s->ptr, new_len + 1);
  s->ptr = ptr_aux;
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return 0; // no memory left
    }
  memcpy (s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

/** @brief Send request
 *
 *  @param[in] conn    struct holding the openvasd connector information
 *  @param[in] method  request method (e.g. GET)
 *  @param[in] path    Path to the resource (e.g. /vts)
 *  @param[in] data    String containing the request body in json format (scan
 * action, scan config)
 *  @param[in] header_name If this field is set, is looked in the header and
 *                         its value is returned
 *
 *  @return Return struct containing the http response code and the response
 * body. In case of error the struct is filled with code RESP_CODE_ERR (-1) and
 * a message. NULL on memory related error. Response must be free()'ed by the
 * caller with openvasd_response_free()
 */
static openvasd_resp_t
openvasd_send_request (openvasd_connector_t *conn, openvasd_req_method_t method,
                       char *path, char *data, const char *header_name)
{
  CURL *curl;
  GString *url = NULL;
  long http_code = RESP_CODE_ERR;
  struct string resp;
  struct curl_slist *customheader = NULL;
  GString *xapikey = NULL;
  openvasd_resp_t response;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  if ((curl = curl_easy_init ()) == NULL)
    {
      response->code = http_code;
      response->body =
        g_strdup ("{\"error\": \"Not possible to initialize curl library\"}");
      g_warning ("%s: Not possible to initialize curl library", __func__);
      return response;
    }

  url = g_string_new (g_strdup ((*conn)->server));

  if ((*conn)->port > 0 && (*conn)->port < 65535)
    {
      char buf[6];
      g_snprintf (buf, sizeof (buf), ":%d", (*conn)->port);
      g_string_append (url, buf);
    }

  if (path != NULL && path[0] != '\0')
    g_string_append (url, path);

  g_debug ("%s: URL: %s", __func__, url->str);
  // Set URL
  if (curl_easy_setopt (curl, CURLOPT_URL, g_strdup (url->str)) != CURLE_OK)
    {
      g_warning ("%s: Not possible to set the URL", __func__);
      curl_easy_cleanup (curl);
      response->code = http_code;
      response->body = g_strdup ("{\"error\": \"Not possible to set URL\"}");
      return response;
    }
  g_string_free (url, TRUE);

  // Server verification
  if ((*conn)->ca_cert != NULL)
    {
      struct curl_blob blob;
      blob.data = (*conn)->ca_cert;
      blob.len = strlen ((*conn)->ca_cert);
      blob.flags = CURL_BLOB_COPY;

      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 1L);
      if (curl_easy_setopt (curl, CURLOPT_CAINFO_BLOB, &blob) != CURLE_OK)
        {
          g_warning ("%s: Not possible to set the CA certificate", __func__);
          curl_easy_cleanup (curl);
          response->code = http_code;
          response->body =
            g_strdup ("{\"error\": \"Not possible to set CA certificate\"}");
          return response;
        }
    }
  else
    {
      // Accept an insecure connection. Don't verify the server certificate
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt (curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
    }

  // Client certificate
  if ((*conn)->cert != NULL && (*conn)->key != NULL)
    {
      struct curl_blob blob;
      blob.data = (*conn)->cert;
      blob.len = strlen ((*conn)->cert);
      blob.flags = CURL_BLOB_COPY;

      if (curl_easy_setopt (curl, CURLOPT_SSLCERT_BLOB, &blob) != CURLE_OK)
        {
          g_warning ("%s: Not possible to set the Client certificate",
                     __func__);
          curl_easy_cleanup (curl);
          response->code = http_code;
          response->body = g_strdup (
            "{\"error\": \"Not possible to set Client certificate\"}");
          return response;
        }
      blob.data = (*conn)->key;
      blob.len = strlen ((*conn)->key);
      blob.flags = CURL_BLOB_COPY;

      if (curl_easy_setopt (curl, CURLOPT_SSLKEY_BLOB, &blob) != CURLE_OK)
        {
          g_warning ("%s: Not possible to set the Client private key",
                     __func__);
          curl_easy_cleanup (curl);
          response->code = http_code;
          response->body = g_strdup (
            "{\"error\": \"Not possible to set Client private key\"}");
          return response;
        }
    }

  // Set API KEY
  if ((*conn)->apikey)
    {
      xapikey = g_string_new ("X-API-KEY: ");
      g_string_append (xapikey, (*conn)->apikey);
      customheader = curl_slist_append (customheader, g_strdup (xapikey->str));
      g_string_free (xapikey, TRUE);
    }

  switch (method)
    {
    case POST:
      if (data != NULL && data[0] != '\0')
        {
          // SET Content type
          customheader =
            curl_slist_append (customheader, "Content-Type: application/json");
          // Set body
          curl_easy_setopt (curl, CURLOPT_POSTFIELDS, data);
          curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen (data));
        }
      break;
    case GET:
      curl_easy_setopt (curl, CURLOPT_HTTPGET, 1L);
      break;
    case DELETE:
      curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "DELETE");
      break;
    default:
      curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "HEAD");
      break;
    };

  if (customheader != NULL)
    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, customheader);

  // Init the struct where the response is stored and set the callback function
  init_string (&resp);
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, response_callback_fn);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &resp);

  int ret = CURLE_OK;
  if ((ret = curl_easy_perform (curl)) != CURLE_OK)
    {
      g_warning ("%s: Error sending request: %d", __func__, ret);
      curl_easy_cleanup (curl);
      g_free (resp.ptr);
      response->code = http_code;
      response->body = g_strdup ("{\"error\": \"Error sending request\"}");
      return response;
    }

  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (header_name && *header_name)
    {
      struct curl_header *hname;
      curl_easy_header (curl, header_name, 0, CURLH_HEADER, -1, &hname);
      response->header = g_strdup (hname->value);
    }
  curl_easy_cleanup (curl);
  g_debug ("%ld - Server response %s", http_code, resp.ptr);
  response->code = http_code;
  response->body = g_strdup (resp.ptr);
  g_free (resp.ptr);

  return response;
}

openvasd_resp_t
openvasd_get_version (openvasd_connector_t *conn)
{
  return openvasd_send_request (conn, HEAD, "/", NULL, NULL);
}

openvasd_resp_t
openvasd_get_vts (openvasd_connector_t *conn)
{
  GString *path;
  openvasd_resp_t response = NULL;

  path = g_string_new ("/vts?information=1");

  response = openvasd_send_request (conn, GET, path->str, NULL, NULL);
  g_string_free (path, TRUE);

  if (response == NULL)
    return NULL;
  else if (response->code == RESP_CODE_ERR)
    return response;

  return response;
}

openvasd_resp_t
openvasd_start_scan (openvasd_connector_t *conn, char *data)
{
  openvasd_resp_t response = NULL;
  JsonParser *parser = NULL;
  JsonReader *reader = NULL;
  GError *err = NULL;
  GString *path;

  response = openvasd_send_request (conn, POST, "/scans", data, NULL);

  if (response == NULL)
    return NULL;
  else if (response->code == RESP_CODE_ERR)
    return response;

  // Get the Scan ID
  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, response->body,
                                   strlen (response->body), &err))
    {
      response->code = RESP_CODE_ERR;
      response->body =
        g_strdup ("{\"error\": \"Parsing json string to get the scan ID\"}");
      g_warning ("%s: Parsing json string to get the scan ID", __func__);
      goto cleanup_start_scan;
    }

  reader = json_reader_new (json_parser_get_root (parser));

  (*conn)->scan_id = g_strdup (json_reader_get_string_value (reader));

  // Start the scan
  path = g_string_new ("/scans");
  if ((*conn)->scan_id != NULL && (*conn)->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, (*conn)->scan_id);
    }
  else
    {
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      goto cleanup_start_scan;
    }

  response = openvasd_send_request (conn, POST, path->str,
                                    "{\"action\": \"start\"}", NULL);
  g_string_free (path, TRUE);
cleanup_start_scan:
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);

  return response;
}

openvasd_resp_t
openvasd_stop_scan (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  GString *path;

  // Stop the scan
  path = g_string_new ("/scans");
  if ((*conn)->scan_id != NULL && (*conn)->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, (*conn)->scan_id);
    }
  else
    {
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = openvasd_send_request (conn, POST, path->str,
                                    "{\"action\": \"stop\"}", NULL);
  g_string_free (path, TRUE);

  return response;
}

openvasd_resp_t
openvasd_get_scan_results (openvasd_connector_t *conn, long first, long last)
{
  openvasd_resp_t response = NULL;
  GString *path = NULL;

  path = g_string_new ("/scans");
  if ((*conn)->scan_id != NULL && (*conn)->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, (*conn)->scan_id);
      if (last > first)
        g_string_append_printf (path, "/results?range%ld-%ld", first, last);
      else if (last < first)
        g_string_append_printf (path, "/results?range=%ld", first);
      else
        g_string_append (path, "/results");
    }
  else
    {
      response = g_malloc0 (sizeof (struct openvasd_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = openvasd_send_request (conn, GET, path->str, NULL, NULL);
  if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan results\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Not possible to get scan results", __func__);
      return response;
    }
  g_string_free (path, TRUE);

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
  if (!result)
    return NULL;

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

gchar *
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
openvasd_result_free (openvasd_result_t *result)
{
  if (result == NULL)
    return;

  g_free ((*result)->type);
  g_free ((*result)->ip_address);
  g_free ((*result)->hostname);
  g_free ((*result)->oid);
  g_free ((*result)->protocol);
  g_free ((*result)->message);
  g_free ((*result)->detail_name);
  g_free ((*result)->detail_value);
  g_free ((*result)->detail_source_name);
  g_free ((*result)->detail_source_type);
  g_free ((*result)->detail_source_description);
  g_free (*result);
  result = NULL;
}

int
openvasd_parsed_results (openvasd_connector_t *conn, unsigned long first,
                         unsigned long last, GSList **results)
{
  JsonParser *parser;
  JsonReader *reader = NULL;
  GError *err = NULL;
  openvasd_resp_t resp = NULL;
  openvasd_result_t result = NULL;
  int results_count = 0;
  unsigned long id;
  gchar *type = NULL;
  gchar *ip_address = NULL;
  gchar *hostname = NULL;
  gchar *oid = NULL;
  int port;
  gchar *protocol = NULL;
  gchar *message = NULL;
  gchar *detail_name = NULL;
  gchar *detail_value = NULL;
  gchar *detail_source_type = NULL;
  gchar *detail_source_name = NULL;
  gchar *detail_source_description = NULL;
  int ret = -1;

  resp = openvasd_get_scan_results (conn, first, last);

  if (resp->code != 200)
    return resp->code;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, resp->body, strlen (resp->body),
                                   &err))
    {
      goto cleanup;
    }
  reader = json_reader_new (json_parser_get_root (parser));

  if (!json_reader_is_array (reader))
    {
      // No results. No information.
      goto cleanup;
    }

  results_count = json_reader_count_elements (reader);
  for (int i = 0; i < results_count; i++)
    {
      json_reader_read_element (reader, i);
      if (!json_reader_is_object (reader))
        {
          // error
          goto cleanup;
        }

      json_reader_read_member (reader, "id");
      id = json_reader_get_int_value (reader);
      json_reader_end_member (reader);

      json_reader_read_member (reader, "type");
      type = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      json_reader_read_member (reader, "ip_address");
      ip_address = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      json_reader_read_member (reader, "hostname");
      hostname = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      json_reader_read_member (reader, "oid");
      oid = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      json_reader_read_member (reader, "port");
      port = json_reader_get_int_value (reader);
      json_reader_end_member (reader);

      json_reader_read_member (reader, "protocol");
      protocol = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      json_reader_read_member (reader, "message");
      message = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      if (json_reader_read_member (reader, "detail"))
        {
          json_reader_read_member (reader, "name");
          detail_name = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);

          json_reader_read_member (reader, "value");
          detail_value = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);

          json_reader_read_member (reader, "source");

          json_reader_read_member (reader, "type");
          detail_source_type = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);

          json_reader_read_member (reader, "name");
          detail_source_name = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);

          json_reader_read_member (reader, "description");
          detail_source_description =
            g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);

          json_reader_end_member (reader); // end source member
        }

      json_reader_end_member (reader);  // end detail
      json_reader_end_element (reader); // end single result element

      result = openvasd_result_new (
        id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, detail_source_type, detail_source_name,
        detail_source_description);

      *results = g_slist_append (*results, result);
      ret = resp->code;
    }

cleanup:
  openvasd_response_free (resp);
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse scan results. Reason: %s", __func__,
                 err->message);
    }

  return ret;
}

openvasd_resp_t
openvasd_get_scan_status (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  GString *path = NULL;

  path = g_string_new ("/scans");
  if ((*conn)->scan_id != NULL && (*conn)->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, (*conn)->scan_id);
      g_string_append (path, "/status");
    }
  else
    {
      response = g_malloc0 (sizeof (struct openvasd_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = openvasd_send_request (conn, GET, path->str, NULL, NULL);
  if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan status\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Not possible to get scan status", __func__);
      return response;
    }
  g_string_free (path, TRUE);

  return response;
}

/** @brief Get the value from an object or error.
 *
 *  @return 0 on success, -1 on error.
 */
static int
get_member_value_or_fail (JsonReader *reader, const char *member)
{
  int value;
  if (!json_reader_read_member (reader, member))
    return -1;

  value = json_reader_get_int_value (reader);
  json_reader_end_member (reader);

  return value;
}

static int
openvasd_get_scan_progress_ext (openvasd_connector_t *conn,
                                openvasd_resp_t response)
{
  JsonParser *parser;
  JsonReader *reader = NULL;
  GError *err = NULL;
  int all = 0, excluded = 0, dead = 0, alive = 0, queued = 0, finished = 0;
  int running_hosts_progress_sum = 0;

  openvasd_resp_t resp;
  int progress = -1;

  if (!response && !(*conn))
    return -1;

  if (response == NULL)
    resp = openvasd_get_scan_status (conn);
  else
    resp = response;

  if (resp->code == 404)
    return -2;
  else if (resp->code != 200)
    return -1;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, resp->body, strlen (resp->body),
                                   &err))
    {
      goto cleanup;
    }
  reader = json_reader_new (json_parser_get_root (parser));

  if (!json_reader_read_member (reader, "host_info"))
    {
      goto cleanup;
    }
  if (!json_reader_is_object (reader))
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
  if (json_reader_read_member (reader, "scanning")
      && json_reader_is_object (reader))
    {
      char **running_hosts = json_reader_list_members (reader);
      for (int i = 0; running_hosts[i]; i++)
        {
          json_reader_read_member (reader, running_hosts[i]);
          running_hosts_progress_sum += json_reader_get_int_value (reader);
          json_reader_end_member (reader);
        }
      g_strfreev (running_hosts);
      json_reader_end_member (reader); // end scanning
    }

  json_reader_end_member (reader); // end host_info

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
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse scan status. Reason: %s", __func__,
                 err->message);
    }
  return progress;
}

int
openvasd_get_scan_progress (openvasd_connector_t *conn)
{
  return openvasd_get_scan_progress_ext (conn, NULL);
}

/** @brief Return a struct with the general scan status
 *
 *  @param conn Openvasd connector data
 *
 *  @return The data in a struct. The struct must be free with g_free()
 *          by the caller.
 */
openvasd_scan_status_t
openvasd_parsed_scan_status (openvasd_connector_t *conn)
{
  JsonParser *parser;
  JsonReader *reader = NULL;
  GError *err = NULL;
  openvasd_resp_t resp;
  gchar *status = NULL;
  time_t start_time = 0, end_time = 0;
  int progress = -1;
  openvasd_status_t status_code = OPENVASD_SCAN_STATUS_ERROR;
  openvasd_scan_status_t status_info;

  resp = openvasd_get_scan_status (conn);

  status_info = g_malloc0 (sizeof (struct openvasd_scan_status));
  if (resp->code != 200)
    {
      status_info->status = status_code;
      status_info->response_code = resp->code;
      openvasd_response_free (resp);
      return status_info;
    }
  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, resp->body, strlen (resp->body),
                                   &err))
    goto cleanup;

  reader = json_reader_new (json_parser_get_root (parser));

  json_reader_read_member (reader, "status");
  status = g_strdup (json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "start_time");
  if (!json_reader_get_null_value (reader))
    start_time = json_reader_get_double_value (reader);
  json_reader_end_member (reader);

  json_reader_read_member (reader, "end_time");
  if (!json_reader_get_null_value (reader))
    end_time = json_reader_get_double_value (reader);
  json_reader_end_member (reader);

  progress = openvasd_get_scan_progress_ext (NULL, resp);

cleanup:
  openvasd_response_free (resp);
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse scan status. Reason: %s", __func__,
                 err->message);
    }

  if (g_strcmp0 (status, "stored") == 0)
    status_code = OPENVASD_SCAN_STATUS_STORED;
  else if (g_strcmp0 (status, "requested") == 0)
    status_code = OPENVASD_SCAN_STATUS_REQUESTED;
  else if (g_strcmp0 (status, "running") == 0)
    status_code = OPENVASD_SCAN_STATUS_RUNNING;
  else if (g_strcmp0 (status, "stopped") == 0)
    status_code = OPENVASD_SCAN_STATUS_STOPPED;
  else if (g_strcmp0 (status, "succeeded") == 0)
    status_code = OPENVASD_SCAN_STATUS_SUCCEEDED;
  else if (g_strcmp0 (status, "succeeded") == 0)
    status_code = OPENVASD_SCAN_STATUS_FAILED;

  g_free (status);

  status_info->status = status_code;
  status_info->end_time = end_time;
  status_info->start_time = start_time;
  status_info->progress = progress;

  return status_info;
}

openvasd_resp_t
openvasd_delete_scan (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  GString *path;

  // Stop the scan
  path = g_string_new ("/scans");
  if ((*conn)->scan_id != NULL && (*conn)->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, (*conn)->scan_id);
    }
  else
    {
      response = g_malloc0 (sizeof (struct openvasd_response));
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  response = openvasd_send_request (conn, DELETE, path->str, NULL, NULL);
  g_string_free (path, TRUE);

  return response;
}

openvasd_resp_t
openvasd_get_health_alive (openvasd_connector_t *conn)
{
  return openvasd_send_request (conn, GET, "/health/alive", NULL, NULL);
}

openvasd_resp_t
openvasd_get_health_ready (openvasd_connector_t *conn)
{
  return openvasd_send_request (conn, GET, "/health/ready", NULL,
                                "feed-version");
}

openvasd_resp_t
openvasd_get_health_started (openvasd_connector_t *conn)
{
  return openvasd_send_request (conn, GET, "/health/started", NULL, NULL);
}

// Scan config builder
static void
add_port_to_scan_json (gpointer range, gpointer builder)
{
  range_t *ports = range;

  json_builder_begin_object ((JsonBuilder *) builder);
  json_builder_set_member_name (builder, "protocol");
  if (ports->type == 1)
    builder = json_builder_add_string_value (builder, "udp");
  else
    builder = json_builder_add_string_value (builder, "tcp");

  json_builder_set_member_name (builder, "range");
  json_builder_begin_array (builder); // ranges array

  json_builder_begin_object (builder); // begin range

  json_builder_set_member_name (builder, "start");
  builder = json_builder_add_int_value (builder, ports->start);

  if (ports->end > ports->start && ports->end < 65535)
    {
      json_builder_set_member_name (builder, "end");
      builder = json_builder_add_int_value (builder, ports->end);
    }

  json_builder_end_object (builder); // end range

  json_builder_end_array (builder); // ranges array

  json_builder_end_object (builder);
}

static void
add_credential_to_scan_json (gpointer credential, gpointer builder)
{
  GHashTableIter auth_data_iter;
  gchar *auth_data_name, *auth_data_value;

  openvasd_credential_t *cred = credential;

  json_builder_begin_object ((JsonBuilder *) builder); // start credential

  json_builder_set_member_name (builder, "service");
  builder = json_builder_add_string_value (builder, cred->service);

  if (cred->port)
    {
      json_builder_set_member_name (builder, "port");
      builder = json_builder_add_int_value (builder, atoi (cred->port));
    }

  json_builder_set_member_name (builder, cred->type);
  json_builder_begin_object (
    (JsonBuilder *) builder); // open type for auth data

  g_hash_table_iter_init (&auth_data_iter, cred->auth_data);
  while (g_hash_table_iter_next (&auth_data_iter, (gpointer *) &auth_data_name,
                                 (gpointer *) &auth_data_value))
    {
      json_builder_set_member_name (builder, auth_data_name);
      builder = json_builder_add_string_value (builder, auth_data_value);
    }
  json_builder_end_object (builder); // end type auth data

  json_builder_end_object (builder); // end credential
}

static void
add_scan_preferences_to_scan_json (gpointer key, gpointer val, gpointer builder)
{
  json_builder_begin_object ((JsonBuilder *) builder); // start preference
  json_builder_set_member_name (builder, "id");
  builder = json_builder_add_string_value (builder, key);
  json_builder_set_member_name (builder, "value");
  builder = json_builder_add_string_value (builder, val);
  json_builder_end_object (builder); // end
}

static void
add_vts_to_scan_json (gpointer single_vt, gpointer builder)
{
  GHashTableIter vt_data_iter;
  gchar *vt_param_id, *vt_param_value;

  openvasd_vt_single_t *vt = single_vt;

  json_builder_begin_object ((JsonBuilder *) builder); // start vt

  json_builder_set_member_name (builder, "oid");
  json_builder_add_string_value (builder, vt->vt_id);

  if (g_hash_table_size (vt->vt_values))
    {
      json_builder_set_member_name (builder, "parameters");
      json_builder_begin_array (
        (JsonBuilder *) builder); // begin parameter list

      g_hash_table_iter_init (&vt_data_iter, vt->vt_values);
      while (g_hash_table_iter_next (&vt_data_iter, (gpointer *) &vt_param_id,
                                     (gpointer *) &vt_param_value))
        {
          json_builder_begin_object (builder); // begin single param
          json_builder_set_member_name (builder, "id");
          json_builder_add_int_value (builder, atoi (vt_param_id));
          json_builder_set_member_name (builder, "value");
          json_builder_add_string_value (builder, vt_param_value);
          json_builder_end_object (builder); // end single param
        }
      json_builder_end_array ((JsonBuilder *) builder); // End parameters list
    }
  json_builder_end_object ((JsonBuilder *) builder); // end vt
}

/**
 * @brief Build a json object with data necessary to start a scan
 *
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param target      target
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
gchar *
openvasd_build_scan_config_json (openvasd_target_t *target,
                                 GHashTable *scan_preferences, GSList *vts)
{
  JsonBuilder *builder;
  JsonGenerator *gen;
  JsonNode *root;
  gchar *json_str;

  /* Build the message in json format to be published. */
  builder = json_builder_new ();

  // begin json
  json_builder_begin_object (builder);

  if (target->scan_id && target->scan_id[0] != '\0')
    {
      json_builder_set_member_name (builder, "scan_id");
      json_builder_add_string_value (builder, target->scan_id);
    }

  // begin target
  json_builder_set_member_name (builder, "target");
  json_builder_begin_object (builder);

  // hosts:
  json_builder_set_member_name (builder, "hosts");
  json_builder_begin_array (builder);
  gchar **hosts_list = g_strsplit (target->hosts, ",", 0);
  for (int i = 0; hosts_list[i] != NULL; i++)
    builder = json_builder_add_string_value (builder, hosts_list[0]);
  g_strfreev (hosts_list);
  json_builder_end_array (builder); // end host

  // exclude hosts
  if (target->exclude_hosts && target->exclude_hosts[0] != '\0')
    {
      json_builder_set_member_name (builder, "excluded_hosts");
      json_builder_begin_array (builder);
      hosts_list = g_strsplit (target->exclude_hosts, ",", 0);
      for (int i = 0; hosts_list[i] != NULL; i++)
        builder = json_builder_add_string_value (builder, hosts_list[0]);
      g_strfreev (hosts_list);
      json_builder_end_array (builder); // end excluded host
    }

  // finished hosts
  if (target->finished_hosts && target->finished_hosts[0] != '\0')
    {
      json_builder_set_member_name (builder, "finished_hosts");
      json_builder_begin_array (builder);
      hosts_list = g_strsplit (target->finished_hosts, ",", 0);
      for (int i = 0; hosts_list[i] != NULL; i++)
        builder = json_builder_add_string_value (builder, hosts_list[0]);
      g_strfreev (hosts_list);
      json_builder_end_array (builder); // end finished host
    }

  // ports
  if (target->ports && target->ports[0 != '\0'])
    {
      json_builder_set_member_name (builder, "ports");
      json_builder_begin_array (builder);
      array_t *ports = port_range_ranges (target->ports);
      g_ptr_array_foreach (ports, add_port_to_scan_json, builder);
      array_free (ports);
      json_builder_end_array (builder); // end ports
    }

  // credentials
  json_builder_set_member_name (builder, "credentials");
  json_builder_begin_array (builder);
  g_slist_foreach (target->credentials, add_credential_to_scan_json, builder);
  json_builder_end_array (builder); // end credentials

  // reverse lookup
  json_builder_set_member_name (builder, "reverse_lookup_unify");
  if (target->reverse_lookup_unify)
    builder = json_builder_add_boolean_value (builder, TRUE);
  else
    builder = json_builder_add_boolean_value (builder, FALSE);

  json_builder_set_member_name (builder, "reverse_lookup_only");

  if (target->reverse_lookup_only)
    builder = json_builder_add_boolean_value (builder, TRUE);
  else
    builder = json_builder_add_boolean_value (builder, FALSE);

  // alive test methods
  json_builder_set_member_name (builder, "alive_test_methods");
  json_builder_begin_array (builder);
  if (target->arp)
    builder = json_builder_add_string_value (builder, "arp");
  if (target->tcp_ack)
    builder = json_builder_add_string_value (builder, "tcp_ack");
  if (target->tcp_syn)
    builder = json_builder_add_string_value (builder, "tcp_syn");
  if (target->consider_alive)
    builder = json_builder_add_string_value (builder, "consider_alive");
  if (target->icmp)
    builder = json_builder_add_string_value (builder, "icmp");
  json_builder_end_array (builder); // end alive methods

  json_builder_end_object (builder); // end target

  // Begin Scan Preferences
  json_builder_set_member_name (builder, "scan_preferences");
  json_builder_begin_array (builder);
  g_hash_table_foreach (scan_preferences, add_scan_preferences_to_scan_json,
                        builder);
  json_builder_end_array (builder); // end preferences array

  // Begin VTs
  json_builder_set_member_name (builder, "vts");
  json_builder_begin_array (builder);
  g_slist_foreach (vts, add_vts_to_scan_json, builder);
  json_builder_end_array (builder); // end vts array

  json_builder_end_object (builder); // end json

  gen = json_generator_new ();
  root = json_builder_get_root (builder);
  json_generator_set_root (gen, root);
  json_str = json_generator_to_data (gen, NULL);

  json_node_free (root);
  g_object_unref (gen);
  g_object_unref (builder);

  if (json_str == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);

  return json_str;
}

/**
 * @brief Create a new Openvasd parameter.
 *
 * @return New Openvasd parameter.
 */
openvasd_param_t *
openvasd_param_new (void)
{
  return g_malloc0 (sizeof (openvasd_param_t));
}

/**
 * @brief Free an Openvasd parameter.
 *
 * @param[in] param Openvasd parameter to destroy.
 */
void
openvasd_param_free (openvasd_param_t *param)
{
  if (!param)
    return;
  g_free (param->id);
  g_free (param->value);
}

/**
 * @brief Allocate and initialize a new Openvasd credential.
 *
 * @param[in]   type      The credential type.
 * @param[in]   service   The service the credential is for.
 * @param[in]   port      The port.
 *
 * @return New openvasd credential.
 */
openvasd_credential_t *
openvasd_credential_new (const char *type, const char *service,
                         const char *port)
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
 * @brief Free an Openvasd credential.
 *
 * @param[in]   credential  The credential to free.
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
 * @brief Get authentication data from an Openvasd credential.
 *
 * @param[in]  credential  The credential to get the data from.
 * @param[in]  name        The name of the data item to get.
 * @param[in]  value       The authentication data or NULL to unset.
 */
void
openvasd_credential_set_auth_data (openvasd_credential_t *credential,
                                   const char *name, const char *value)
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
 * @brief Create a new Openvasd target.
 *
 * @param[in]  hosts          The hostnames of the target.
 * @param[in]  ports          The ports of the target.
 * @param[in]  exclude_hosts  The excluded hosts of the target.
 * @param[in]  alive_test     The alive test method of the target.
 * @param[in]  reverse_lookup_unify  Lookup flag.
 * @param[in]  reverse_lookup_only   Lookup flag.
 *
 * @return The newly allocated openvasd_target_t.
 */
openvasd_target_t *
openvasd_target_new (const char *scanid, const char *hosts, const char *ports,
                     const char *exclude_hosts, int reverse_lookup_unify,
                     int reverse_lookup_only)
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
 * @brief Set the finished hosts of an Openvasd target.
 *
 * @param[in]  target         The Openvasd target to modify.
 * @param[in]  finished_hosts The hostnames to consider finished.
 */
void
openvasd_target_set_finished_hosts (openvasd_target_t *target,
                                    const char *finished_hosts)
{
  g_free (target->finished_hosts);
  target->finished_hosts = finished_hosts ? g_strdup (finished_hosts) : NULL;
}

/**
 * @brief Free an Openvasd target, including all added credentials.
 *
 * @param[in]  target  The Openvasd target to free.
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
 * @brief Add alive test methods to Openvasd target.
 *
 * @param[in]  target           The Openvasd target to add the methods to.
 * @param[in]  icmp             Use ICMP ping.
 * @param[in]  tcp_syn          Use TCP-SYN ping.
 * @param[in]  tcp_ack          Use TCP-ACK ping.
 * @param[in]  arp              Use ARP ping.
 * @param[in]  consider_alive   Consider host to be alive.
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
 * @brief Add a credential to an Openvasd target.
 *
 * @param[in]  target       The Openvasd target to add the credential to.
 * @param[in]  credential   The credential to add. Will be freed with target.
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
 * @brief Create a new single Openvasd VT.
 *
 * @param[in]  vt_id  The id of the VT.
 *
 * @return  The newly allocated single VT.
 */
openvasd_vt_single_t *
openvasd_vt_single_new (const char *vt_id)
{
  openvasd_vt_single_t *new_vt_single;
  new_vt_single = g_malloc0 (sizeof (openvasd_vt_single_t));

  new_vt_single->vt_id = vt_id ? g_strdup (vt_id) : NULL;
  new_vt_single->vt_values =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_vt_single;
}

/**
 * @brief Free a single Openvasd VT, including all preference values.
 *
 * @param[in]  vt_single  The Openvasd VT to free.
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
 * @brief Add a preference value to an Openvasd VT.
 * This creates a copy of the name and value.
 *
 * @param[in]  vt_single  The VT to add the preference to.
 * @param[in]  name       The name / identifier of the preference.
 * @param[in]  value      The value of the preference.
 */
void
openvasd_vt_single_add_value (openvasd_vt_single_t *vt_single, const char *name,
                              const char *value)
{
  g_hash_table_replace (vt_single->vt_values, g_strdup (name),
                        g_strdup (value));
}
