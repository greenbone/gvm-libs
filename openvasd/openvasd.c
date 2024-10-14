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

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <netinet/in.h>
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
 * @brief Struct holding the data for connecting with Openvasd.
 */
struct openvasd_connector
{
  char *ca_cert; /**< Path to the directory holding the CA certificate. */
  char *cert;    /**< Client certificate. */
  char *key;     /**< Client key. */
  char *apikey;  /**< API key for authentication. */
  char *server;  /**< original openvasd server URL. */
  char *host;    /**< server hostname. */
  char *scan_id; /**< Scan ID. */
  int port;      /**< server port. */
};

/**
 * @brief Struct holding options for Openvasd parameters.
 */
struct openvasd_param
{
  char *id;          /**< Parameter id. */
  char *name;        /**< Parameter name. */
  char *defval;      /**< Default value. */
  char *description; /**< Description. */
  char *type;        /**< Parameter type. */
  int mandatory;     /**< If mandatory. */
};

/**
 * @brief Struct credential information for Openvasd.
 */
struct openvasd_credential
{
  char *type;            /**< Credential type */
  char *service;         /**< Service the credential is for */
  char *port;            /**< Port the credential is for */
  GHashTable *auth_data; /**< Authentication data (username, password, etc.)*/
};

/**
 * @brief Struct holding target information.
 */
struct openvasd_target
{
  char *scan_id;            /**  Scan ID */
  GSList *credentials;      /** Credentials to use in the scan */
  char *exclude_hosts;      /** String defining one or many hosts to exclude */
  char *hosts;              /** String defining one or many hosts to scan */
  char *ports;              /** String defining the ports to scan */
  char *finished_hosts;     /** String defining hosts to exclude as finished */
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
  char *vt_id;
  GHashTable *vt_values;
};

/**
 * @brief Request methods
 */
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

/**
 * @brief Free an openvasd response struct
 *
 * @param resp Response to be free()'d
 */
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

/** @brief Initialize the string struct to hold the response
 *
 *  @param s[in/out] The string struct to be initialized
 */
void
init_openvasd_stringstream (openvasd_stringstream *s)
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

/** @brief Reinitialize the string struct to hold the response
 *
 *  @param s[in/out] The string struct to be initialized
 */
static void
reset_openvasd_stringstream (openvasd_stringstream *s)
{
  g_free (s->ptr);
  init_openvasd_stringstream (s);
}

/** @brief Call back function to stored the response.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the response in s. It reallocate memory if necessary.
 */
static size_t
response_callback_fn (void *ptr, size_t size, size_t nmemb, void *struct_string)
{
  openvasd_stringstream *s = struct_string;
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

/** @brief Create a CURL handler
 *
 *  @param[in] conn    struct holding the openvasd connector information
 *  @param[in] method  request method (e.g. GET)
 *  @param[in] path    Path to the resource (e.g. /vts)
 *  @param[in] data    String containing the request body in json format (scan
 * action, scan config)
 *  @param[out] resp   Structure holding the body response, filled by the
 * callback function
 *  @param[out] err    On error, this variable is filled with an error message
 * in json format.
 *
 * @return a CURL handler, or NULL on error.
 */
static CURL *
handler (openvasd_connector_t *conn, openvasd_req_method_t method, char *path,
         char *data, openvasd_stringstream *resp, char **err)
{
  CURL *curl;
  GString *url = NULL;
  struct curl_slist *customheader = NULL;
  GString *xapikey = NULL;

  if (!conn)
    {
      *err = g_strdup ("{\"error\": \"Missing openvasd connector\"}");
      g_warning ("%s: Missing openvasd connector", __func__);
      return NULL;
    }

  if ((curl = curl_easy_init ()) == NULL)
    {
      *err =
        g_strdup ("{\"error\": \"Not possible to initialize curl library\"}");
      g_warning ("%s: Not possible to initialize curl library", __func__);
      return NULL;
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

  // Set URL
  g_debug ("%s: URL: %s", __func__, url->str);
  if (curl_easy_setopt (curl, CURLOPT_URL, g_strdup (url->str)) != CURLE_OK)
    {
      g_warning ("%s: Not possible to set the URL", __func__);
      curl_easy_cleanup (curl);
      *err = g_strdup ("{\"error\": \"Not possible to set URL\"}");
      return NULL;
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
          *err =
            g_strdup ("{\"error\": \"Not possible to set CA certificate\"}");
          return NULL;
        }
    }
  else
    {
      // Accept an insecure connection. Don't verify the server certificate
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt (curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
      g_debug ("%s: Server certificate verification disabled.", __func__);
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
          *err = g_strdup (
            "{\"error\": \"Not possible to set Client certificate\"}");
          return NULL;
        }
      blob.data = (*conn)->key;
      blob.len = strlen ((*conn)->key);
      blob.flags = CURL_BLOB_COPY;

      if (curl_easy_setopt (curl, CURLOPT_SSLKEY_BLOB, &blob) != CURLE_OK)
        {
          g_warning ("%s: Not possible to set the Client private key",
                     __func__);
          curl_easy_cleanup (curl);
          *err = g_strdup (
            "{\"error\": \"Not possible to set Client private key\"}");
          return NULL;
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
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, response_callback_fn);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, resp);

  return curl;
}

/** @brief Send request
 *
 *  @param[in] curl        The CURL handler to perform an request.
 *  @param[in] header_name If this field is set, is looked in the header and
 *                         its value is returned inside the response.
 *  @param[out] response   The response struct to be filled with the response
 * code and the header value.
 *
 *  @return Return struct containing the http response code and the response
 * body. In case of error the struct is filled with code RESP_CODE_ERR (-1) and
 * a message. NULL on memory related error. Response must be free()'ed by the
 * caller with openvasd_response_free()
 */
static openvasd_resp_t
openvasd_send_request (CURL *curl, const char *header_name,
                       openvasd_resp_t response)
{
  long http_code = RESP_CODE_ERR;

  int ret = CURLE_OK;
  if ((ret = curl_easy_perform (curl)) != CURLE_OK)
    {
      g_warning ("%s: Error sending request: %d", __func__, ret);
      curl_easy_cleanup (curl);
      curl = NULL;
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
  curl = NULL;
  response->code = http_code;

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
openvasd_get_version (openvasd_connector_t *conn)
{
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_resp_t response = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, HEAD, "/", NULL, &resp, &err)) == NULL)
    {
      response->code = RESP_CODE_ERR;
      response->body = err;
      g_free (resp.ptr);
      return response;
    }

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);

  g_free (resp.ptr);
  return response;
}
/**
 * @brief Wrapps a CURLM * handler
 */
openvasd_curlm_t
openvasd_curlm_handler_new (void)
{
  CURLM *h = NULL;
  return h;
}

void
openvasd_curl_handler_close (openvasd_curlm_t *h)
{
  int queued = 0;

  /* when an easy handle has completed, remove it */
  CURLMsg *msg = curl_multi_info_read (h, &queued);
  if (msg)
    {
      if (msg->msg == CURLMSG_DONE)
        {
          curl_multi_remove_handle (h, msg->easy_handle);
          curl_easy_cleanup (msg->easy_handle);
          curl_multi_cleanup (h);
          return;
        }
      g_warning ("%s: Not possible to clean up the curl handler", __func__);
    }
}

/**
 * @brief Initialized an curl multiperform handler which allows fetch feed
 * metadata chunk by chunk.
 *
 * @param conn[in] Connector struct with the data necessary for the connection
 * @param mhnd[out] The curl multiperform handler
 * @param resp[out] The stringstream struct for the write callback function.
 *
 * @return The response. Null on error.
 */
openvasd_resp_t
openvasd_get_vts_stream_init (openvasd_connector_t *conn,
                              openvasd_curlm_t *mhnd,
                              openvasd_stringstream *resp)
{
  GString *path;
  openvasd_resp_t response = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  CURLM *h = NULL;
  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  path = g_string_new ("/vts?information=1");
  if ((hnd = handler (conn, GET, path->str, NULL, resp, &err)) == NULL)
    {
      g_string_free (path, TRUE);
      g_free (resp->ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  h = curl_multi_init ();
  curl_multi_add_handle (h, hnd);
  *mhnd = h;

  response->code = RESP_CODE_OK;
  return response;
}

/**
 * @brief Get a new feed metadata chunk. This function must be call until the
 * return value is 0, meaning there is no more data to fetch.
 *
 * @param[in] conn Connector struct with the data necessary for the connection
 * @param[in/out] mhnd Curl multiperfom for requesting the feed metadata
 * @param[out] The openvasd_stringstream struct for the write callback function.
 *
 * @return greather than 0 if the handler is still getting data. 0 if the
 * transmision finished. -1 on error
 */
int
openvasd_get_vts_stream (openvasd_curlm_t mhnd)
{
  static int running = 0;
  CURLM *h = mhnd;
  if (!(h))
    {
      return -1;
    }

  CURLMcode mc = curl_multi_perform (h, &running);
  if (!mc && running)
    /* wait for activity, timeout or "nothing" */
    mc = curl_multi_poll (h, NULL, 0, 5000, NULL);
  if (mc != CURLM_OK)
    {
      g_warning ("%s: error on curl_multi_poll(): %d\n", __func__, mc);
      return -1;
    }

  return running;
}

/**
 * @brief Get VT's metadata
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return Response Struct containing the feed metadata in json format in the
 * body. NULL on error.
 */
openvasd_resp_t
openvasd_get_vts (openvasd_connector_t *conn)
{
  GString *path;
  openvasd_resp_t response = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  path = g_string_new ("/vts?information=1");
  if ((hnd = handler (conn, GET, path->str, NULL, &resp, &err)) == NULL)
    {
      g_string_free (path, TRUE);
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  openvasd_send_request (hnd, NULL, response);

  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);

  g_free (resp.ptr);
  return response;
}

/**
 * @brief Get VT's metadata
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return Response Struct containing the feed metadata in json format in the
 * body. NULL on error.
 */
openvasd_resp_t
openvasd_start_scan (openvasd_connector_t *conn, char *data)
{
  openvasd_resp_t response = NULL;
  cJSON *parser = NULL;
  GString *path;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, POST, "/scans", data, &resp, &err)) == NULL)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response == NULL || response->code == RESP_CODE_ERR)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      if (response->body == NULL)
        response->body =
          g_strdup ("{\"error\": \"Storing scan configuration\"}");
      g_warning ("%s: Error storing scan configuration ", __func__);
      return response;
    }

  // Get the Scan ID
  parser = cJSON_Parse (response->body);
  if (!parser)
    {
      const char *error_ptr = cJSON_GetErrorPtr ();
      if (error_ptr != NULL)
        {
          response->body = g_strdup_printf ("{\"error\": \"%s\"}", error_ptr);
          g_warning ("%s: %s", __func__, error_ptr);
        }
      else
        {
          response->body = g_strdup (
            "{\"error\": \"Parsing json string to get the scan ID\"}");
          g_warning ("%s: Parsing json string to get the scan ID", __func__);
        }
      response->code = RESP_CODE_ERR;
      g_free (resp.ptr);
      cJSON_Delete (parser);
      return response;
    }

  (*conn)->scan_id = g_strdup (cJSON_GetStringValue (parser));

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
      cJSON_Delete (parser);
      return response;
    }

  reset_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, POST, path->str, "{\"action\": \"start\"}", &resp,
                      &err))
      == NULL)
    {
      g_free (resp.ptr);
      g_string_free (path, TRUE);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response == NULL || response->code == RESP_CODE_ERR)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      if (response->body == NULL)
        response->body = g_strdup ("{\"error\": \"Starting the scan.\"}");
      g_warning ("%s: Error starting the scan.", __func__);
      return response;
    }

  cJSON_Delete (parser);
  response->body = g_strdup (resp.ptr);
  g_free (resp.ptr);
  return response;
}

openvasd_resp_t
openvasd_stop_scan (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  GString *path;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

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

  init_openvasd_stringstream (&resp);
  if ((hnd =
         handler (conn, POST, path->str, "{\"action\": \"stop\"}", &resp, &err))
      == NULL)
    {
      g_string_free (path, TRUE);
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);

  g_free (resp.ptr);
  return response;
}

openvasd_resp_t
openvasd_get_scan_results (openvasd_connector_t *conn, long first, long last)
{
  openvasd_resp_t response = NULL;
  GString *path = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

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
      response->code = RESP_CODE_ERR;
      response->body = g_strdup ("{\"error\": \"Missing scan ID\"}");
      g_string_free (path, TRUE);
      g_warning ("%s: Missing scan ID", __func__);
      return response;
    }

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, GET, path->str, NULL, &resp, &err)) == NULL)
    {
      g_string_free (path, TRUE);
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      g_warning ("%s: Not possible to get scan results", __func__);
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan results\"}");
    }
  g_free (resp.ptr);

  return response;
}

openvasd_result_t
openvasd_result_new (unsigned long id, char *type, char *ip_address,
                     char *hostname, char *oid, int port, char *protocol,
                     char *message, char *detail_name, char *detail_value,
                     char *detail_source_type, char *detail_source_name,
                     char *detail_source_description)
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
  cJSON *parser = NULL;
  cJSON *result_obj = NULL;
  const char *err = NULL;
  openvasd_resp_t resp = NULL;
  openvasd_result_t result = NULL;
  unsigned long id = 0;
  char *type = NULL;
  char *ip_address = NULL;
  char *hostname = NULL;
  char *oid = NULL;
  int port = 0;
  char *protocol = NULL;
  char *message = NULL;
  char *detail_name = NULL;
  char *detail_value = NULL;
  char *detail_source_type = NULL;
  char *detail_source_name = NULL;
  char *detail_source_description = NULL;
  int ret = -1;

  resp = openvasd_get_scan_results (conn, first, last);

  if (resp->code != 200)
    return resp->code;

  if ((parser = cJSON_Parse (resp->body)) == NULL)
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
    cJSON *item = NULL;
    if (!cJSON_IsObject (result_obj))
      // error
      goto res_cleanup;

    if ((item = cJSON_GetObjectItem (result_obj, "id")) != NULL
        && cJSON_IsNumber (item))
      id = item->valuedouble;

    if ((item = cJSON_GetObjectItem (result_obj, "type")) != NULL
        && cJSON_IsString (item))
      type = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (result_obj, "ip_address")) != NULL
        && cJSON_IsString (item))
      ip_address = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (result_obj, "hostname")) != NULL
        && cJSON_IsString (item))
      hostname = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (result_obj, "oid")) != NULL
        && cJSON_IsString (item))
      oid = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (result_obj, "port")) != NULL
        && cJSON_IsNumber (item))
      port = item->valueint;

    if ((item = cJSON_GetObjectItem (result_obj, "protocol")) != NULL
        && cJSON_IsString (item))
      protocol = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (result_obj, "message")) != NULL
        && cJSON_IsString (item))
      message = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (result_obj, "detail")) != NULL
        && cJSON_IsObject (item))
      {
        cJSON *detail_obj = NULL;

        if ((detail_obj = cJSON_GetObjectItem (item, "name")) != NULL
            && cJSON_IsString (detail_obj))
          detail_name = g_strdup (detail_obj->valuestring);

        if ((detail_obj = cJSON_GetObjectItem (item, "value")) != NULL
            && cJSON_IsString (detail_obj))
          detail_value = g_strdup (detail_obj->valuestring);

        cJSON *source_obj = NULL;
        if ((source_obj = cJSON_GetObjectItem (detail_obj, "type")) != NULL
            && cJSON_IsObject (source_obj))
          detail_source_type = g_strdup (detail_obj->valuestring);

        if ((source_obj = cJSON_GetObjectItem (detail_obj, "name")) != NULL
            && cJSON_IsString (source_obj))
          detail_source_name = g_strdup (detail_obj->valuestring);

        if ((source_obj = cJSON_GetObjectItem (detail_obj, "description"))
              != NULL
            && cJSON_IsString (source_obj))
          detail_source_description = g_strdup (detail_obj->valuestring);
      }

    result = openvasd_result_new (id, type, ip_address, hostname, oid, port,
                                  protocol, message, detail_name, detail_value,
                                  detail_source_type, detail_source_name,
                                  detail_source_description);

    *results = g_slist_append (*results, result);
    ret = resp->code;
  }

res_cleanup:
  openvasd_response_free (resp);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse scan results. Reason: %s", __func__, err);
    }
  cJSON_Delete (parser);

  return ret;
}

openvasd_resp_t
openvasd_get_scan_status (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  GString *path = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  path = g_string_new ("/scans");
  if ((*conn)->scan_id != NULL && (*conn)->scan_id[0] != '\0')
    {
      g_string_append (path, "/");
      g_string_append (path, (*conn)->scan_id);
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

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, GET, path->str, NULL, &resp, &err)) == NULL)
    {
      g_string_free (path, TRUE);
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scan status\"}");
      g_warning ("%s: Not possible to get scan status", __func__);
    }

  g_free (resp.ptr);
  return response;
}

/** @brief Get the value from an object or error.
 *
 *  @return 0 on success, -1 on error.
 */
static int
get_member_value_or_fail (cJSON *reader, const char *member)
{
  cJSON *item = NULL;
  if ((item = cJSON_GetObjectItem (reader, member)) == NULL
      && cJSON_IsNumber (item))
    return -1;

  return item->valueint;
}

static int
openvasd_get_scan_progress_ext (openvasd_connector_t *conn,
                                openvasd_resp_t response)
{
  cJSON *parser;
  cJSON *reader = NULL;
  const char *err = NULL;
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

  parser = cJSON_Parse (resp->body);
  if (!parser)
    {
      err = cJSON_GetErrorPtr ();
      goto cleanup;
    }

  if ((reader = cJSON_GetObjectItem (parser, "host_info")) == NULL)
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
  cJSON *scanning = NULL;
  if ((scanning = cJSON_GetObjectItem (reader, "scanning")) != NULL
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
openvasd_get_scan_progress (openvasd_connector_t *conn)
{
  return openvasd_get_scan_progress_ext (conn, NULL);
}

static openvasd_status_t
get_status_code_from_openvas (const char *status_val)
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
  cJSON *parser = NULL;
  cJSON *status = NULL;
  openvasd_resp_t resp = NULL;
  char *status_val = NULL;
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
  if ((parser = cJSON_Parse (resp->body)) == NULL)
    goto status_cleanup;

  if ((status = cJSON_GetObjectItem (parser, "status")) == NULL
      || !cJSON_IsString (status))
    goto status_cleanup;
  status_val = g_strdup (status->valuestring);

  if ((status = cJSON_GetObjectItem (parser, "start_time")) != NULL
      && !cJSON_IsNumber (status))
    start_time = status->valuedouble;

  if ((status = cJSON_GetObjectItem (parser, "end_time")) != NULL
      && !cJSON_IsNumber (status))
    end_time = status->valuedouble;

  progress = openvasd_get_scan_progress_ext (NULL, resp);

status_cleanup:
  openvasd_response_free (resp);
  cJSON_Delete (parser);

  status_code = get_status_code_from_openvas (status_val);
  g_free (status_val);

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
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

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

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, DELETE, path->str, NULL, &resp, &err)) == NULL)
    {
      g_string_free (path, TRUE);
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }
  g_string_free (path, TRUE);

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to delete scan.\"}");
      g_warning ("%s: Not possible to delete scan", __func__);
    }

  g_free (resp.ptr);
  return response;
}

openvasd_resp_t
openvasd_get_health_alive (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, GET, "/health/alive", NULL, &resp, &err)) == NULL)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  g_free (resp.ptr);
  return response;
}

openvasd_resp_t
openvasd_get_health_ready (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, GET, "/health/ready", NULL, &resp, &err)) == NULL)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }

  openvasd_send_request (hnd, "feed-version", response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  g_free (resp.ptr);
  return response;
}

openvasd_resp_t
openvasd_get_health_started (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, GET, "/health/started", NULL, &resp, &err)) == NULL)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get health information.\"}");
      g_warning ("%s: Not possible to get health information", __func__);
    }

  g_free (resp.ptr);
  return response;
}

openvasd_resp_t
openvasd_get_scan_preferences (openvasd_connector_t *conn)
{
  openvasd_resp_t response = NULL;
  char *err = NULL;
  CURL *hnd = NULL;
  openvasd_stringstream resp;

  response = g_malloc0 (sizeof (struct openvasd_response));
  if (response == NULL)
    return NULL;

  init_openvasd_stringstream (&resp);
  if ((hnd = handler (conn, GET, "/scans/preferences", NULL, &resp, &err))
      == NULL)
    {
      g_free (resp.ptr);
      response->code = RESP_CODE_ERR;
      response->body = err;
      return response;
    }

  openvasd_send_request (hnd, NULL, response);
  if (response != NULL && response->code != RESP_CODE_ERR)
    response->body = g_strdup (resp.ptr);
  else if (response->code == RESP_CODE_ERR)
    {
      response->body =
        g_strdup ("{\"error\": \"Not possible to get scans preferences.\"}");
      g_warning ("%s: Not possible to get scans_preferences", __func__);
    }

  g_free (resp.ptr);
  return response;
}

/**
 * @brief Create a new Openvasd parameter.
 *
 * @return New Openvasd parameter.
 */
static openvasd_param_t *
openvasd_param_new (char *id, char *name, char *defval, char *description,
                    char *type, int mandatory)
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
  g_free (param->name);
  g_free (param->defval);
  g_free (param->description);
  g_free (param->type);
}

/**
 * @brief Get the parameter id
 *
 * @param[in] param Openvasd parameter
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
 * @param[in] param Openvasd parameter
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
 * @param[in] param Openvasd parameter
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
 * @param[in] param Openvasd parameter
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
 * @param[in] param Openvasd parameter
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
 * @param[in] param Openvasd parameter
 */
int
openvasd_param_mandatory (openvasd_param_t *param)
{
  if (!param)
    return 0;

  return param->mandatory;
}

int
openvasd_parsed_scans_preferences (openvasd_connector_t *conn, GSList **params)
{
  openvasd_resp_t resp = NULL;
  cJSON *parser;
  cJSON *param_obj = NULL;
  int err = 0;

  resp = openvasd_get_scan_preferences (conn);

  if (resp->code != 200)
    return -1;

  // No results. No information.
  if ((parser = cJSON_Parse (resp->body)) == NULL || !cJSON_IsArray (parser))
    {
      err = 1;
      goto prefs_cleanup;
    }

  cJSON_ArrayForEach (param_obj, parser)
  {
    const char *id = NULL, *name = NULL, *desc = NULL;
    char *defval = NULL, *param_type = NULL;
    openvasd_param_t *param = NULL;
    int val, mandatory = 0;
    char buf[6];
    cJSON *item = NULL;
    if ((item = cJSON_GetObjectItem (param_obj, "id")) != NULL
        && cJSON_IsString (item))
      id = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (param_obj, "name")) != NULL
        && cJSON_IsString (item))
      name = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (param_obj, "description")) != NULL
        && cJSON_IsString (item))
      desc = g_strdup (item->valuestring);

    if ((item = cJSON_GetObjectItem (param_obj, "default")) != NULL)
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
      openvasd_param_new (g_strdup (id), g_strdup (name), g_strdup (defval),
                          g_strdup (desc), g_strdup (param_type), mandatory);
    g_free (defval);
    g_free (param_type);
    *params = g_slist_append (*params, param);
  }

prefs_cleanup:
  openvasd_response_free (resp);
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
  char *auth_data_name, *auth_data_value;
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
  char *vt_param_id, *vt_param_value;

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
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param target      target
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
  char *json_str = NULL;

  /* Build the message in json format to be published. */
  scan_obj = cJSON_CreateObject ();

  if (target->scan_id && target->scan_id[0] != '\0')
    cJSON_AddStringToObject (scan_obj, "scan_id", target->scan_id);

  // begin target
  target_obj = cJSON_CreateObject ();

  // hosts
  hosts_array = cJSON_CreateArray ();
  char **hosts_list = g_strsplit (target->hosts, ",", 0);
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
      char **exclude_hosts_list = g_strsplit (target->exclude_hosts, ",", 0);
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
      char **finished_hosts_list = g_strsplit (target->finished_hosts, ",", 0);
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
