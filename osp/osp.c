/* Copyright (C) 2014-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file
 * @brief API for Open Scanner Protocol communication.
 */

#include "osp.h"

#include "../base/hosts.h"       /* for gvm_get_host_type */
#include "../util/serverutils.h" /* for gvm_server_close, gvm_server_open_w... */

#include <assert.h>        /* for assert */
#include <gnutls/gnutls.h> /* for gnutls_session_int, gnutls_session_t */
#include <stdarg.h>        /* for va_list */
#include <stdio.h>         /* for FILE, fprintf and related functions */
#include <stdlib.h>        /* for NULL, atoi */
#include <string.h>        /* for strcmp, strlen, strncpy */
#include <sys/socket.h>    /* for AF_UNIX, connect, socket, SOCK_STREAM */
#include <sys/un.h>        /* for sockaddr_un, sa_family_t */
#include <unistd.h>        /* for close */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  osp"

/**
 * @brief Struct holding options for OSP connection.
 */
struct osp_connection
{
  gnutls_session_t session; /**< Pointer to GNUTLS Session. */
  int socket;               /**< Socket. */
  char *host;               /**< Host. */
  int port;                 /**< Port. */
};

/**
 * @brief Struct holding options for OSP parameters.
 */
struct osp_param
{
  char *id;              /**< Parameter id. */
  char *name;            /**< Parameter name. */
  char *desc;            /**< Parameter description. */
  char *def;             /**< Default value. */
  osp_param_type_t type; /**< Parameter type. */
  int mandatory;         /**< If mandatory or not. */
};

/**
 * @brief Struct credential information for OSP.
 */
struct osp_credential
{
  gchar *type;           /**< Credential type */
  gchar *service;        /**< Service the credential is for */
  gchar *port;           /**< Port the credential is for */
  GHashTable *auth_data; /**< Authentication data (username, password, etc.)*/
};

/**
 * @brief Struct holding target information.
 */
struct osp_target
{
  GSList *credentials;      /** Credentials to use in the scan */
  gchar *exclude_hosts;     /** String defining one or many hosts to exclude */
  gchar *hosts;             /** String defining one or many hosts to scan */
  gchar *ports;             /** String defining the ports to scan */
  gchar *finished_hosts;    /** String defining hosts to exclude as finished */
  int alive_test;           /** Value defining an alive test method */
  int reverse_lookup_unify; /** Value defining reverse_lookup_unify opt */
  int reverse_lookup_only;  /** Value defining reverse_lookup_only opt */
};

/**
 * @brief Struct holding vt_group information
 */
struct osp_vt_group
{
  gchar *filter;
};

/**
 * @brief Struct holding vt_group information
 */
struct osp_vt_single
{
  gchar *vt_id;
  GHashTable *vt_values;
};

static int
osp_send_command (osp_connection_t *, entity_t *, const char *, ...)
  __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * @brief Open a new connection to an OSP server.
 *
 * @param[in]   host    Host of OSP server.
 * @param[in]   port    Port of OSP server.
 * @param[in]   cacert  CA public key.
 * @param[in]   cert    Client public key.
 * @param[in]   key     Client private key.
 *
 * @return New osp connection, NULL if error.
 */
osp_connection_t *
osp_connection_new (const char *host, int port, const char *cacert,
                    const char *cert, const char *key)
{
  osp_connection_t *connection;

  if (host && *host == '/')
    {
      struct sockaddr_un addr;
      int len;

      connection = g_malloc0 (sizeof (*connection));
      connection->socket = socket (AF_UNIX, SOCK_STREAM, 0);
      if (connection->socket == -1)
        return NULL;

      addr.sun_family = AF_UNIX;
      strncpy (addr.sun_path, host, sizeof (addr.sun_path) - 1);
      len = strlen (addr.sun_path) + sizeof (addr.sun_family);
      if (connect (connection->socket, (struct sockaddr *) &addr, len) == -1)
        {
          close (connection->socket);
          return NULL;
        }
    }
  else
    {
      if (port <= 0 || port > 65535)
        return NULL;
      if (!host || gvm_get_host_type (host) == -1)
        return NULL;
      if (!cert || !key || !cacert)
        return NULL;

      connection = g_malloc0 (sizeof (*connection));
      connection->socket = gvm_server_open_with_cert (
        &connection->session, host, port, cacert, cert, key);
    }
  if (connection->socket == -1)
    {
      g_free (connection);
      return NULL;
    }

  connection->host = g_strdup (host);
  connection->port = port;
  return connection;
}

/**
 * @brief Send a command to an OSP server.
 *
 * @param[in]   connection  Connection to OSP server.
 * @param[out]  response    Response from OSP server.
 * @param[in]   fmt         OSP Command to send.
 *
 * @return 0 and response, 1 if error.
 */
int
osp_send_command (osp_connection_t *connection, entity_t *response,
                  const char *fmt, ...)
{
  va_list ap;
  int rc = 1;

  va_start (ap, fmt);

  if (!connection || !fmt || !response)
    goto out;

  if (*connection->host == '/')
    {
      if (gvm_socket_vsendf (connection->socket, fmt, ap) == -1)
        goto out;
      if (read_entity_s (connection->socket, response))
        goto out;
    }
  else
    {
      if (gvm_server_vsendf (&connection->session, fmt, ap) == -1)
        goto out;
      if (read_entity (&connection->session, response))
        goto out;
    }

  rc = 0;

out:
  va_end (ap);

  return rc;
}

/**
 * @brief Close a connection to an OSP server.
 *
 * @param[in]   connection  Connection to OSP server to close.
 */
void
osp_connection_close (osp_connection_t *connection)
{
  if (!connection)
    return;

  if (*connection->host == '/')
    close (connection->socket);
  else
    gvm_server_close (connection->socket, connection->session);
  g_free (connection->host);
  g_free (connection);
}

/**
 * @brief Get the scanner version from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[out]  s_name      Parsed scanner name.
 * @param[out]  s_version   Parsed scanner version.
 * @param[out]  d_name      Parsed scanner name.
 * @param[out]  d_version   Parsed scanner version.
 * @param[out]  p_name      Parsed scanner name.
 * @param[out]  p_version   Parsed scanner version.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_get_version (osp_connection_t *connection, char **s_name, char **s_version,
                 char **d_name, char **d_version, char **p_name,
                 char **p_version)
{
  entity_t entity, child, gchild;

  if (!connection)
    return 1;

  if (osp_send_command (connection, &entity, "<get_version/>"))
    return 1;

  child = entity_child (entity, "scanner");
  if (!child)
    goto err_get_version;
  gchild = entity_child (child, "name");
  if (!gchild)
    goto err_get_version;
  if (s_name)
    *s_name = g_strdup (entity_text (gchild));
  gchild = entity_child (child, "version");
  if (!gchild)
    goto err_get_version;
  if (s_version)
    *s_version = g_strdup (entity_text (gchild));

  child = entity_child (entity, "daemon");
  if (!child)
    goto err_get_version;
  gchild = entity_child (child, "name");
  if (!gchild)
    goto err_get_version;
  if (d_name)
    *d_name = g_strdup (entity_text (gchild));
  gchild = entity_child (child, "version");
  if (!gchild)
    goto err_get_version;
  if (d_version)
    *d_version = g_strdup (entity_text (gchild));

  child = entity_child (entity, "protocol");
  if (!child)
    goto err_get_version;
  gchild = entity_child (child, "name");
  if (!gchild)
    goto err_get_version;
  if (p_name)
    *p_name = g_strdup (entity_text (gchild));
  gchild = entity_child (child, "version");
  if (!gchild)
    goto err_get_version;
  if (p_version)
    *p_version = g_strdup (entity_text (gchild));

  free_entity (entity);
  return 0;

err_get_version:
  g_warning ("Erroneous OSP <get_version/> response.");
  if (s_name)
    g_free (*s_name);
  if (s_version)
    g_free (*s_version);
  if (d_name)
    g_free (*d_name);
  if (d_version)
    g_free (*d_version);
  if (p_name)
    g_free (*p_name);
  if (p_version)
    g_free (*p_version);
  free_entity (entity);
  return 1;
}

/**
 * @brief Get the VTs version from an OSP server.
 *
 * @param[in]   connection    Connection to an OSP server.
 * @param[out]  vts_version   Parsed scanner version.
 * @param[out]  error         Pointer to error, if any.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_get_vts_version (osp_connection_t *connection, char **vts_version,
                     char **error)
{
  entity_t entity, vts;
  const char *version;
  const char *status, *status_text;
  osp_get_vts_opts_t get_vts_opts;

  if (!connection)
    return 1;

  get_vts_opts = osp_get_vts_opts_default;
  get_vts_opts.version_only = 1;
  if (osp_get_vts_ext (connection, get_vts_opts, &entity))
    return 1;

  status = entity_attribute (entity, "status");

  if (status != NULL && !strcmp (status, "400"))
    {
      status_text = entity_attribute (entity, "status_text");
      g_debug ("%s: %s - %s.", __func__, status, status_text);
      if (error)
        *error = g_strdup (status_text);
      free_entity (entity);
      return 1;
    }

  vts = entity_child (entity, "vts");
  if (!vts)
    {
      g_warning ("%s: element VTS missing.", __func__);
      free_entity (entity);
      return 1;
    }

  version = entity_attribute (vts, "vts_version");

  if (vts_version)
    *vts_version = g_strdup (version);

  free_entity (entity);
  return 0;
}

/**
 * @brief Get all VTs from an OSP server.
 *
 * @param[in]   connection    Connection to an OSP server.
 * @param[out]  vts           VTs.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_get_vts (osp_connection_t *connection, entity_t *vts)
{
  if (!connection)
    return 1;

  if (vts == NULL)
    return 1;

  if (osp_send_command (connection, vts, "<get_vts/>"))
    return 1;

  return 0;
}

/**
 * @brief Get filtered set of VTs from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   opts        Struct containing the options to apply.
 * @param[out]  vts         VTs.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_get_vts_ext (osp_connection_t *connection, osp_get_vts_opts_t opts,
                 entity_t *vts)
{
  if (!connection)
    return 1;

  if (vts == NULL)
    return 1;

  if (opts.version_only == 1)
    {
      if (osp_send_command (connection, vts, "<get_vts version_only='1'/>"))
        return 1;
      return 0;
    }

  if (opts.filter)
    {
      if (osp_send_command (connection, vts, "<get_vts filter='%s'/>",
                            opts.filter))
        return 1;
      return 0;
    }

  if (osp_send_command (connection, vts, "<get_vts/>"))
    return 1;
  return 0;
}

/**
 * @brief Delete a scan from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to delete.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_delete_scan (osp_connection_t *connection, const char *scan_id)
{
  entity_t entity;
  int ret = 0;
  const char *status;

  if (!connection)
    return 1;

  ret = osp_send_command (connection, &entity, "<delete_scan scan_id='%s'/>",
                          scan_id);
  if (ret)
    return 1;

  /* Check response status. */
  status = entity_attribute (entity, "status");
  assert (status);
  if (strcmp (status, "200"))
    ret = 1;

  free_entity (entity);
  return ret;
}

/**
 * @brief Get performance graphics from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   opts        Struct containing the options to apply.
 * @param[out]  graph       Graphic base64 encoded.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return 0 if success, -1 if error.
 */
int
osp_get_performance_ext (osp_connection_t *connection,
                         osp_get_performance_opts_t opts, char **graph,
                         char **error)
{
  entity_t entity;
  int rc;
  time_t now;

  if (!connection)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_performance command "
                           "to scanner. Not valid connection");
      return -1;
    }

  time (&now);

  if (!opts.titles || !strcmp (opts.titles, "") || opts.start < 0
      || opts.start > now || opts.end < 0 || opts.end > now)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_performance command "
                           "to scanner. Bad or missing parameters.");
      return -1;
    }

  rc = osp_send_command (connection, &entity,
                         "<get_performance start='%d' "
                         "end='%d' titles='%s'/>",
                         opts.start, opts.end, opts.titles);

  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_performance command to scanner");
      return -1;
    }

  if (graph && entity_text (entity) && strcmp (entity_text (entity), "\0"))
    *graph = g_strdup (entity_text (entity));
  else
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }

  free_entity (entity);
  return 0;
}

/**
 * @brief Get a scan status from an OSP server
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to get.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return Osp scan status
 */
osp_scan_status_t
osp_get_scan_status_ext (osp_connection_t *connection,
                         osp_get_scan_status_opts_t opts, char **error)
{
  entity_t entity, child;
  int rc;
  osp_scan_status_t status = OSP_SCAN_STATUS_ERROR;

  if (!connection)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_scans command "
                           "to scanner. Not valid connection");
      return status;
    }

  assert (opts.scan_id);
  rc = osp_send_command (connection, &entity,
                         "<get_scans scan_id='%s'"
                         " details='0'"
                         " pop_results='0'/>",
                         opts.scan_id);

  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_scans command to scanner");
      return status;
    }

  child = entity_child (entity, "scan");
  if (!child)
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return status;
    }

  if (!strcmp (entity_attribute (child, "status"), "queued"))
    status = OSP_SCAN_STATUS_QUEUED;
  else if (!strcmp (entity_attribute (child, "status"), "init"))
    status = OSP_SCAN_STATUS_INIT;
  else if (!strcmp (entity_attribute (child, "status"), "running"))
    status = OSP_SCAN_STATUS_RUNNING;
  else if (!strcmp (entity_attribute (child, "status"), "stopped"))
    status = OSP_SCAN_STATUS_STOPPED;
  else if (!strcmp (entity_attribute (child, "status"), "finished"))
    status = OSP_SCAN_STATUS_FINISHED;
  else if (!strcmp (entity_attribute (child, "status"), "interrupted"))
    status = OSP_SCAN_STATUS_INTERRUPTED;

  free_entity (entity);
  return status;
}

/**
 * @brief Get a scan from an OSP server, optionally removing the results.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to get.
 * @param[out]  report_xml  Scans report.
 * @param[in]   details     0 for no scan details, 1 otherwise.
 * @param[in]   pop_results 0 to leave results, 1 to pop results from scanner.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return Scan progress if success, -1 if error.
 */
int
osp_get_scan_pop (osp_connection_t *connection, const char *scan_id,
                  char **report_xml, int details, int pop_results, char **error)
{
  entity_t entity, child;
  int progress;
  int rc;

  if (!connection)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_scan command "
                           "to scanner. Not valid connection");
      return -1;
    }
  assert (scan_id);
  rc = osp_send_command (connection, &entity,
                         "<get_scans scan_id='%s'"
                         " details='%d'"
                         " pop_results='%d'/>",
                         scan_id, pop_results ? 1 : 0, details ? 1 : 0);
  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_scans command to scanner");
      return -1;
    }

  child = entity_child (entity, "scan");
  if (!child)
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }
  progress = atoi (entity_attribute (child, "progress"));
  if (report_xml)
    {
      GString *string;

      string = g_string_new ("");
      print_entity_to_string (child, string);
      *report_xml = g_string_free (string, FALSE);
    }
  free_entity (entity);
  return progress;
}

/**
 * @brief Get a scan from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to get.
 * @param[out]  report_xml  Scans report.
 * @param[in]   details     0 for no scan details, 1 otherwise.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return Scan progress if success, -1 if error.
 */
int
osp_get_scan (osp_connection_t *connection, const char *scan_id,
              char **report_xml, int details, char **error)
{
  return osp_get_scan_pop (connection, scan_id, report_xml, details, 0, error);
}

/**
 * @brief Stop a scan on an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to delete.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return Scan progress if success, -1 if error.
 */
int
osp_stop_scan (osp_connection_t *connection, const char *scan_id, char **error)
{
  entity_t entity;
  int rc;

  if (!connection)
    {
      if (error)
        *error = g_strdup ("Couldn't send stop_scan command "
                           "to scanner. Not valid connection");
      return -1;
    }
  assert (scan_id);
  rc = osp_send_command (connection, &entity, "<stop_scan scan_id='%s'/>",
                         scan_id);
  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send stop_scan command to scanner");
      return -1;
    }

  rc = atoi (entity_attribute (entity, "status"));
  if (rc == 200)
    {
      free_entity (entity);
      return 0;
    }
  else
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }
}

/**
 * @brief Concatenate options as xml.
 *
 * @param[in]     key      Tag name for xml element.
 * @param[in]     value    Text for xml element.
 * @param[in,out] pstr     Parameters as xml concatenated xml elements.
 *
 */
static void
option_concat_as_xml (gpointer key, gpointer value, gpointer pstr)
{
  char *options_str, *tmp, *key_escaped, *value_escaped;

  options_str = *(char **) pstr;

  key_escaped = g_markup_escape_text ((char *) key, -1);
  value_escaped = g_markup_escape_text ((char *) value, -1);
  tmp = g_strdup_printf ("%s<%s>%s</%s>", options_str ? options_str : "",
                         key_escaped, value_escaped, key_escaped);

  g_free (options_str);
  g_free (key_escaped);
  g_free (value_escaped);
  *(char **) pstr = tmp;
}

/**
 * @brief Start an OSP scan against a target.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   target      Target host to scan.
 * @param[in]   ports       List of ports to scan.
 * @param[in]   options     Table of scan options.
 * @param[in]   scan_id     uuid to set for scan, null otherwise.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return 0 on success, -1 otherwise.
 */
int
osp_start_scan (osp_connection_t *connection, const char *target,
                const char *ports, GHashTable *options, const char *scan_id,
                char **error)
{
  entity_t entity;
  char *options_str = NULL;
  int status;
  int rc;

  if (!connection)
    {
      if (error)
        *error = g_strdup ("Couldn't send start_scan command "
                           "to scanner. Not valid connection");
      return -1;
    }

  assert (target);
  /* Construct options string. */
  if (options)
    g_hash_table_foreach (options, option_concat_as_xml, &options_str);

  rc = osp_send_command (connection, &entity,
                         "<start_scan target='%s' ports='%s' scan_id='%s'>"
                         "<scanner_params>%s</scanner_params></start_scan>",
                         target, ports ? ports : "", scan_id ? scan_id : "",
                         options_str ? options_str : "");
  g_free (options_str);
  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send start_scan command to scanner");
      return -1;
    }

  status = atoi (entity_attribute (entity, "status"));
  if (status == 200)
    {
      free_entity (entity);
      return 0;
    }
  else
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }
}

/**
 * @brief Concatenate a credential as XML.
 *
 * @param[in]     credential  Credential data.
 * @param[in,out] xml_string  XML string buffer to append to.
 *
 */
static void
credential_append_as_xml (osp_credential_t *credential, GString *xml_string)

{
  GHashTableIter auth_data_iter;
  gchar *auth_data_name, *auth_data_value;

  xml_string_append (xml_string,
                     "<credential type=\"%s\" service=\"%s\" port=\"%s\">",
                     credential->type ? credential->type : "",
                     credential->service ? credential->service : "",
                     credential->port ? credential->port : "");

  g_hash_table_iter_init (&auth_data_iter, credential->auth_data);
  while (g_hash_table_iter_next (&auth_data_iter, (gpointer *) &auth_data_name,
                                 (gpointer *) &auth_data_value))
    {
      xml_string_append (xml_string, "<%s>%s</%s>", auth_data_name,
                         auth_data_value, auth_data_name);
    }

  xml_string_append (xml_string, "</credential>");
}

/**
 * @brief Concatenate a target as XML.
 *
 * @param[in]     target      Target data.
 * @param[in,out] xml_string  XML string buffer to append to.
 *
 */
static void
target_append_as_xml (osp_target_t *target, GString *xml_string)
{
  xml_string_append (xml_string,
                     "<target>"
                     "<hosts>%s</hosts>"
                     "<exclude_hosts>%s</exclude_hosts>"
                     "<finished_hosts>%s</finished_hosts>"
                     "<ports>%s</ports>",
                     target->hosts ? target->hosts : "",
                     target->exclude_hosts ? target->exclude_hosts : "",
                     target->finished_hosts ? target->finished_hosts : "",
                     target->ports ? target->ports : "");

  if (target->alive_test > 0)
    xml_string_append (xml_string, "<alive_test>%d</alive_test>",
                       target->alive_test);
  if (target->reverse_lookup_unify == 1)
    xml_string_append (xml_string,
                       "<reverse_lookup_unify>%d</reverse_lookup_unify>",
                       target->reverse_lookup_unify);
  if (target->reverse_lookup_only == 1)
    xml_string_append (xml_string,
                       "<reverse_lookup_only>%d</reverse_lookup_only>",
                       target->reverse_lookup_only);

  if (target->credentials)
    {
      g_string_append (xml_string, "<credentials>");
      g_slist_foreach (target->credentials, (GFunc) credential_append_as_xml,
                       xml_string);
      g_string_append (xml_string, "</credentials>");
    }
  xml_string_append (xml_string, "</target>");
}

/**
 * @brief Append VT groups as XML to a string buffer.
 *
 * @param[in]     vt_group    VT group data.
 * @param[in,out] xml_string  XML string buffer to append to.
 */
static void
vt_group_append_as_xml (osp_vt_group_t *vt_group, GString *xml_string)
{
  xml_string_append (xml_string, "<vt_group filter=\"%s\"/>", vt_group->filter);
}

/**
 * @brief Append VT values as XML to a string buffer.
 *
 * @param[in]     id          Identifier of the vt_value.
 * @param[in]     value       The value of the vt_value.
 * @param[in,out] xml_string  XML string buffer to append to.
 *
 */
static void
vt_value_append_as_xml (gpointer id, gchar *value, GString *xml_string)
{
  xml_string_append (xml_string, "<vt_value id=\"%s\">%s</vt_value>",
                     id ? id : "", value ? value : "");
}

/**
 * @brief Append single VTs as XML to a string buffer.
 *
 * @param[in]     vt_single   Single VT data.
 * @param[in,out] xml_string  XML string buffer to append to.
 */
static void
vt_single_append_as_xml (osp_vt_single_t *vt_single, GString *xml_string)
{
  xml_string_append (xml_string, "<vt_single id=\"%s\">", vt_single->vt_id);
  g_hash_table_foreach (vt_single->vt_values, (GHFunc) vt_value_append_as_xml,
                        xml_string);
  xml_string_append (xml_string, "</vt_single>");
}

/**
 * @brief Start an OSP scan against a target.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   opts        Struct containing the options to apply.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return 0 on success, -1 otherwise.
 */
int
osp_start_scan_ext (osp_connection_t *connection, osp_start_scan_opts_t opts,
                    char **error)
{
  gchar *scanner_params_xml = NULL;
  GString *xml;
  GSList *list_item;
  int list_count;
  int rc, status;
  entity_t entity;
  gchar *cmd;
  char filename[] = "/tmp/osp-cmd-XXXXXX";
  int fd;

  if (!connection)
    {
      if (error)
        *error = g_strdup ("Couldn't send start_scan command "
                           "to scanner. Not valid connection");
      return -1;
    }

  fd = mkstemp (filename);
  FILE *file = fdopen (fd, "w");

  xml = g_string_sized_new (10240);
  g_string_append (xml, "<start_scan");
  xml_string_append (xml, " scan_id=\"%s\">", opts.scan_id ? opts.scan_id : "");

  g_string_append (xml, "<targets>");
  g_slist_foreach (opts.targets, (GFunc) target_append_as_xml, xml);
  g_string_append (xml, "</targets>");

  g_string_append (xml, "<scanner_params>");
  if (opts.scanner_params)
    {
      scanner_params_xml = NULL;
      g_hash_table_foreach (opts.scanner_params, (GHFunc) option_concat_as_xml,
                            &scanner_params_xml);
      if (scanner_params_xml)
        g_string_append (xml, scanner_params_xml);
      g_free (scanner_params_xml);
    }
  g_string_append (xml, "</scanner_params>");

  g_string_append (xml, "<vt_selection>");
  g_slist_foreach (opts.vt_groups, (GFunc) vt_group_append_as_xml, xml);

  fprintf (file, "%s", xml->str);

  g_string_free (xml, TRUE);

  xml = g_string_new ("");
  list_item = opts.vts;
  list_count = 0;
  while (list_item)
    {
      list_count++;
      vt_single_append_as_xml (list_item->data, xml);

      list_item = list_item->next;

      if (list_count == 1000)
        {
          fprintf (file, "%s", xml->str);

          g_string_free (xml, TRUE);
          xml = g_string_new ("");
          list_count = 0;
        }
    }

  g_string_append (xml, "</vt_selection>");
  g_string_append (xml, "</start_scan>");

  fprintf (file, "%s", xml->str);
  fflush (file);
  fclose (file);
  g_string_free (xml, TRUE);

  g_file_get_contents (filename, &cmd, NULL, NULL);

  rc = osp_send_command (connection, &entity, "%s", cmd);

  g_free (cmd);
  unlink (filename);

  if (rc)
    {
      if (error)
        *error = g_strdup ("Could not send start_scan command to scanner");
      return -1;
    }

  status = atoi (entity_attribute (entity, "status"));
  if (status == 200)
    {
      free_entity (entity);
      return 0;
    }
  else
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }

  if (error)
    *error = NULL;
  free_entity (entity);
  return 0;
}

/**
 * @brief Get an OSP parameter's type from its string format.
 *
 * @param[in]   str     OSP parameter in string format.
 *
 * @return OSP parameter type.
 */
static osp_param_type_t
osp_param_str_to_type (const char *str)
{
  assert (str);
  if (!strcmp (str, "integer"))
    return OSP_PARAM_TYPE_INT;
  else if (!strcmp (str, "string"))
    return OSP_PARAM_TYPE_STR;
  else if (!strcmp (str, "password"))
    return OSP_PARAM_TYPE_PASSWORD;
  else if (!strcmp (str, "file"))
    return OSP_PARAM_TYPE_FILE;
  else if (!strcmp (str, "boolean"))
    return OSP_PARAM_TYPE_BOOLEAN;
  else if (!strcmp (str, "ovaldef_file"))
    return OSP_PARAM_TYPE_OVALDEF_FILE;
  else if (!strcmp (str, "selection"))
    return OSP_PARAM_TYPE_SELECTION;
  else if (!strcmp (str, "credential_up"))
    return OSP_PARAM_TYPE_CRD_UP;
  assert (0);
  return 0;
}

/**
 * @brief Get an OSP parameter in string format form its type.
 *
 * @param[in]   param     OSP parameter.
 *
 * @return OSP parameter in string format.
 */
const char *
osp_param_type_str (const osp_param_t *param)
{
  osp_param_type_t type;

  assert (param);
  type = param->type;
  if (type == OSP_PARAM_TYPE_INT)
    return "integer";
  else if (type == OSP_PARAM_TYPE_STR)
    return "string";
  else if (type == OSP_PARAM_TYPE_PASSWORD)
    return "password";
  else if (type == OSP_PARAM_TYPE_FILE)
    return "file";
  else if (type == OSP_PARAM_TYPE_BOOLEAN)
    return "boolean";
  else if (type == OSP_PARAM_TYPE_OVALDEF_FILE)
    return "ovaldef_file";
  else if (type == OSP_PARAM_TYPE_SELECTION)
    return "selection";
  else if (type == OSP_PARAM_TYPE_CRD_UP)
    return "credential_up";
  assert (0);
  return NULL;
}

/**
 * @brief Get an OSP scanner's details.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[out]  desc        Scanner's description.
 * @param[out]  params      Scanner's parameters.
 *
 * @return 0 if success, 1 if failure.
 */
int
osp_get_scanner_details (osp_connection_t *connection, char **desc,
                         GSList **params)
{
  entity_t entity, child;
  entities_t entities;

  assert (connection);

  if (osp_send_command (connection, &entity, "<get_scanner_details/>"))
    return 1;
  if (params)
    {
      child = entity_child (entity, "scanner_params");
      if (!child)
        {
          free_entity (entity);
          return 1;
        }
      entities = child->entities;
      while (entities)
        {
          osp_param_t *param;

          child = entities->data;
          param = osp_param_new ();
          param->id = g_strdup (entity_attribute (child, "id"));
          param->type =
            osp_param_str_to_type (entity_attribute (child, "type"));
          param->name = g_strdup (entity_text (entity_child (child, "name")));
          param->desc =
            g_strdup (entity_text (entity_child (child, "description")));
          param->def = g_strdup (entity_text (entity_child (child, "default")));
          if (entity_child (child, "mandatory"))
            param->mandatory =
              atoi (entity_text (entity_child (child, "mandatory")));
          *params = g_slist_append (*params, param);
          entities = next_entities (entities);
        }
    }
  if (desc)
    {
      child = entity_child (entity, "description");
      assert (child);
      *desc = g_strdup (entity_text (child));
    }

  free_entity (entity);
  return 0;
}

/**
 * @brief Create a new OSP parameter.
 *
 * @return New OSP parameter.
 */
osp_param_t *
osp_param_new (void)
{
  return g_malloc0 (sizeof (osp_param_t));
}

/**
 * @brief Get an OSP parameter's id.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return ID of OSP parameter.
 */
const char *
osp_param_id (const osp_param_t *param)
{
  assert (param);

  return param->id;
}

/**
 * @brief Get an OSP parameter's name.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Name of OSP parameter.
 */
const char *
osp_param_name (const osp_param_t *param)
{
  assert (param);

  return param->name;
}

/**
 * @brief Get an OSP parameter's description.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Description of OSP parameter.
 */
const char *
osp_param_desc (const osp_param_t *param)
{
  assert (param);

  return param->desc;
}

/**
 * @brief Get an OSP parameter's default value.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Default value of OSP parameter.
 */
const char *
osp_param_default (const osp_param_t *param)
{
  assert (param);

  return param->def;
}

/**
 * @brief Get an OSP parameter's mandatory value.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Mandatory value of OSP parameter.
 */
int
osp_param_mandatory (const osp_param_t *param)
{
  assert (param);

  return param->mandatory;
}

/**
 * @brief Free an OSP parameter.
 *
 * @param[in] param OSP parameter to destroy.
 */
void
osp_param_free (osp_param_t *param)
{
  if (!param)
    return;
  g_free (param->id);
  g_free (param->name);
  g_free (param->desc);
  g_free (param->def);
  g_free (param);
}

/**
 * @brief Allocate and initialize a new OSP credential.
 *
 * @param[in]   type      The credential type.
 * @param[in]   service   The service the credential is for.
 * @param[in]   port      The port.
 *
 * @return New osp credential.
 */
osp_credential_t *
osp_credential_new (const char *type, const char *service, const char *port)
{
  osp_credential_t *new_credential;

  new_credential = g_malloc0 (sizeof (osp_credential_t));

  new_credential->type = type ? g_strdup (type) : NULL;
  new_credential->service = service ? g_strdup (service) : NULL;
  new_credential->port = port ? g_strdup (port) : NULL;
  new_credential->auth_data =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_credential;
}

/**
 * @brief Free an OSP credential.
 *
 * @param[in]   credential  The credential to free.
 */
void
osp_credential_free (osp_credential_t *credential)
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
 * @brief Get authentication data from an OSP credential.
 *
 * @param[in]  credential  The credential to get the data from.
 * @param[in]  name        The name of the data item to get.
 *
 * @return The requested authentication data or NULL if not available.
 */
const gchar *
osp_credential_get_auth_data (osp_credential_t *credential, const char *name)
{
  if (credential == NULL || name == NULL)
    return NULL;
  return g_hash_table_lookup (credential->auth_data, name);
}

/**
 * @brief Get authentication data from an OSP credential.
 *
 * @param[in]  credential  The credential to get the data from.
 * @param[in]  name        The name of the data item to get.
 * @param[in]  value       The authentication data or NULL to unset.
 */
void
osp_credential_set_auth_data (osp_credential_t *credential, const char *name,
                              const char *value)
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
 * @brief Create a new OSP target.
 *
 * @param[in]  hosts          The hostnames of the target.
 * @param[in]  ports          The ports of the target.
 * @param[in]  exclude_hosts  The excluded hosts of the target.
 * @param[in]  alive_test     The alive test method of the target.
 *
 * @return The newly allocated osp_target_t.
 */
osp_target_t *
osp_target_new (const char *hosts, const char *ports, const char *exclude_hosts,
                int alive_test, int reverse_lookup_unify,
                int reverse_lookup_only)
{
  osp_target_t *new_target;
  new_target = g_malloc0 (sizeof (osp_target_t));

  new_target->exclude_hosts = exclude_hosts ? g_strdup (exclude_hosts) : NULL;
  new_target->hosts = hosts ? g_strdup (hosts) : NULL;
  new_target->ports = ports ? g_strdup (ports) : NULL;
  new_target->finished_hosts = NULL;
  new_target->alive_test = alive_test ? alive_test : 0;
  new_target->reverse_lookup_unify =
    reverse_lookup_unify ? reverse_lookup_unify : 0;
  new_target->reverse_lookup_only =
    reverse_lookup_only ? reverse_lookup_only : 0;

  return new_target;
}

/**
 * @brief Set the finished hosts of an OSP target.
 *
 * @param[in]  target         The OSP target to modify.
 * @param[in]  finished_hosts The hostnames to consider finished.
 */
void
osp_target_set_finished_hosts (osp_target_t *target, const char *finished_hosts)
{
  g_free (target->finished_hosts);
  target->finished_hosts = finished_hosts ? g_strdup (finished_hosts) : NULL;
}

/**
 * @brief Free an OSP target, including all added credentials.
 *
 * @param[in]  target  The OSP target to free.
 */
void
osp_target_free (osp_target_t *target)
{
  if (!target)
    return;

  g_slist_free_full (target->credentials, (GDestroyNotify) osp_credential_free);
  g_free (target->exclude_hosts);
  g_free (target->hosts);
  g_free (target->ports);
  g_free (target);
}

/**
 * @brief Add a credential to an OSP target.
 *
 * @param[in]  target       The OSP target to add the credential to.
 * @param[in]  credential   The credential to add. Will be freed with target.
 */
void
osp_target_add_credential (osp_target_t *target, osp_credential_t *credential)
{
  if (!target || !credential)
    return;

  target->credentials = g_slist_prepend (target->credentials, credential);
}

/**
 * @brief Create a new OSP VT group.
 *
 * @param[in]  filter  The filter string for the VT group.
 *
 * @return  The newly allocated VT group.
 */
osp_vt_group_t *
osp_vt_group_new (const char *filter)
{
  osp_vt_group_t *new_vt_group;
  new_vt_group = g_malloc0 (sizeof (osp_vt_group_t));

  new_vt_group->filter = filter ? g_strdup (filter) : NULL;

  return new_vt_group;
}

/**
 * @brief Free a OSP VT group.
 *
 * @param[in]  vt_group  The VT group to free.
 */
void
osp_vt_group_free (osp_vt_group_t *vt_group)
{
  if (!vt_group)
    return;

  g_free (vt_group->filter);
  g_free (vt_group);
}

/**
 * @brief Create a new single OSP VT.
 *
 * @param[in]  vt_id  The id of the VT.
 *
 * @return  The newly allocated single VT.
 */
osp_vt_single_t *
osp_vt_single_new (const char *vt_id)
{
  osp_vt_single_t *new_vt_single;
  new_vt_single = g_malloc0 (sizeof (osp_vt_single_t));

  new_vt_single->vt_id = vt_id ? g_strdup (vt_id) : NULL;
  new_vt_single->vt_values =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_vt_single;
}

/**
 * @brief Free a single OSP VT, including all preference values.
 *
 * @param[in]  vt_single  The OSP VT to free.
 */
void
osp_vt_single_free (osp_vt_single_t *vt_single)
{
  if (!vt_single)
    return;

  g_hash_table_destroy (vt_single->vt_values);

  g_free (vt_single->vt_id);
  g_free (vt_single);
}

/**
 * @brief Add a preference value to an OSP VT.
 * This creates a copy of the name and value.
 *
 * @param[in]  vt_single  The VT to add the preference to.
 * @param[in]  name       The name / identifier of the preference.
 * @param[in]  value      The value of the preference.
 */
void
osp_vt_single_add_value (osp_vt_single_t *vt_single, const char *name,
                         const char *value)
{
  g_hash_table_replace (vt_single->vt_values, g_strdup (name),
                        g_strdup (value));
}
