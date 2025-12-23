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
#include "../http_scanner/http_scanner.h"
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

/**
 * @brief Fetch feed metadata chunk by chunk.
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return The response.
 */
http_scanner_resp_t
openvasd_get_vt_stream_init (http_scanner_connector_t conn)
{
  GString *path;
  http_scanner_resp_t response = NULL;

  path = g_string_new ("/vts?information=1");
  response = http_scanner_init_request_multi (conn, path->str);

  g_string_free (path, TRUE);

  return response;
}

/**
 * @brief Get a new feed metadata chunk.
 *
 * This function must be call until the
 * return value is 0, meaning there is no more data to fetch.
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return greather than 0 if the handler is still getting data. 0 if the
 * transmision finished. -1 on error
 */
int
openvasd_get_vt_stream (http_scanner_connector_t conn)
{
  return http_scanner_process_request_multi (conn, 5000);
}

/**
 * @brief Get VT's metadata
 *
 * @param conn Connector struct with the data necessary for the connection
 *
 * @return Response Struct containing the feed metadata in json format in the
 * body.
 */
http_scanner_resp_t
openvasd_get_vts (http_scanner_connector_t conn)
{
  GString *path;
  http_scanner_resp_t response = NULL;

  path = g_string_new ("/vts?information=1");
  response =
    http_scanner_send_request (conn, HTTP_SCANNER_GET, path->str, NULL, NULL);

  g_string_free (path, TRUE);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Get performance data.
 *
 * @param conn Connector struct with the data necessary for the connection.
 * @param opts Options for the performance request.
 *
 * @return Response Struct containing the performance data.
 */
http_scanner_resp_t
openvasd_get_performance (http_scanner_connector_t conn,
                          openvasd_get_performance_opts_t opts)
{
  http_scanner_resp_t response;
  gchar *query;
  time_t now;

  time (&now);

  if (!opts.titles || !strcmp (opts.titles, "") || opts.start < 0
      || opts.start > now || opts.end < 0 || opts.end > now)
    {
      response = g_malloc0 (sizeof (struct http_scanner_response));
      response->code = RESP_CODE_ERR;
      response->body =
        g_strdup ("{\"error\": \"Couldn't send get_performance command "
                  "to scanner. Bad or missing parameters.\"}");
      return response;
    }

  query = g_strdup_printf ("/health/performance?start=%d&end=%d&titles=%s",
                           opts.start, opts.end, opts.titles);
  response =
    http_scanner_send_request (conn, HTTP_SCANNER_GET, query, NULL, NULL);
  g_free (query);

  if (response->code != RESP_CODE_ERR)
    response->body = g_strdup (http_scanner_stream_str (conn));
  else
    {
      response->body = g_strdup (
        "{\"error\": \"Not possible to get performance information.\"}");
      g_warning ("%s: Not possible to get performance information", __func__);
    }

  http_scanner_reset_stream (conn);
  return response;
}

/**
 * @brief Parse performance data.
 *
 * @param conn Connector struct with the data necessary for the connection.
 * @param opts Options for the performance request.
 * @param graph Pointer to store the graph data.
 * @param err Pointer to store error message if any.
 *
 * @return 0 on success, -1 on error.
 */
int
openvasd_parsed_performance (http_scanner_connector_t conn,
                             openvasd_get_performance_opts_t opts,
                             gchar **graph, gchar **err)
{
  http_scanner_resp_t resp = NULL;
  cJSON *parser;
  cJSON *item;
  int ret = 0;
  resp = openvasd_get_performance (conn, opts);

  // No results. No information.
  parser = cJSON_Parse (resp->body);
  if (parser == NULL)
    {
      *err = g_strdup ("Unable to parse sensor performance data");
      ret = -1;
    }
  else if (resp->code != 200)
    {
      parser = cJSON_Parse (resp->body);
      item = cJSON_GetObjectItem (parser, "error");
      if (item != NULL)
        *err = g_strdup (cJSON_GetStringValue (item));
      ret = -1;
    }
  else
    {
      item = cJSON_GetArrayItem (parser, 0);
      if (item != NULL)
        *graph = g_strdup (cJSON_GetStringValue (item));
    }

  http_scanner_response_cleanup (resp);
  cJSON_Delete (parser);

  return ret;
}

// Scan config builder.

/**
 * @brief Add a port range to the scan json object.
 *
 * @param range Port range to add.
 * @param p_array JSON array to add the port range to.
 */
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

/**
 * @brief Add a credential to the scan json object.
 *
 * @param credentials Credential to add.
 * @param cred_array JSON array to add the credential to.
 */
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

/**
 * @brief Add a scan preference to the scan json object.
 *
 * @param key Preference ID.
 * @param val Preference value.
 * @param scan_prefs_array JSON array to add the preference to.
 */
static void
add_scan_preferences_to_scan_json (gpointer key, gpointer val,
                                   gpointer scan_prefs_array)
{
  cJSON *pref_obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (pref_obj, "id", key);
  cJSON_AddStringToObject (pref_obj, "value", val);
  cJSON_AddItemToArray (scan_prefs_array, pref_obj);
}

/**
 * @brief Add a VT to the scan json object.
 *
 * @param single_vt VT to add.
 * @param vts_array JSON array to add the VT to.
 */
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
 * @return The newly allocated single VT.
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
