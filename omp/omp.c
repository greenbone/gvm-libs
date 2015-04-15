/* openvase-libraries/omp
 * $Id$
 * Description: OMP client interface.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

/** @todo Name functions consistently (perhaps omp_*). */

/**
 * @file omp.c
 * @brief OMP client interface.
 *
 * This provides higher level, OMP-aware, facilities for working with with
 * the OpenVAS manager.
 *
 * There are examples of using this interface in the openvas-manager tests.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#define sleep Sleep
#endif

#include <errno.h>

#include "omp.h"
#include "xml.h"
#include "openvas_server.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib   omp"

#define OMP_FMT_BOOL_ATTRIB(var, attrib)            \
  (var.attrib == 0 ? " " #attrib "=\"0\"" : " " #attrib "=\"1\"")

#define OMP_FMT_STRING_ATTRIB(var, attrib) \
  (var.attrib ? " " #attrib "= \"" : ""),  \
  (var.attrib ? var.attrib : ""),          \
  (var.attrib ? "\"" : "")


/* Local XML interface extension. */

/** @todo Use next_entities and first_entity instead of this. */

/**
 * @brief Do something for each child of an entity.
 *
 * Calling "break" during body exits the loop.
 *
 * @param[in]  entity  The entity.
 * @param[in]  child   Name to use for child variable.
 * @param[in]  temp    Name to use for internal variable.
 * @param[in]  body    The code to run for each child.
 */
#define DO_CHILDREN(entity, child, temp, body)      \
  do                                                \
    {                                               \
      GSList* temp = entity->entities;              \
      while (temp)                                  \
        {                                           \
          entity_t child = temp->data;              \
          {                                         \
            body;                                   \
          }                                         \
          temp = g_slist_next (temp);               \
        }                                           \
    }                                               \
  while (0)

#if 0
/* Lisp version of DO_CHILDREN. */
(defmacro do-children ((entity child) &body body)
  "Do something for each child of an entity."
  (let ((temp (gensym)))
    `(while ((,temp (entity-entities ,entity) (rest ,temp)))
            (,temp)
       ,@body)))
#endif


/* OMP. */

/**
 * @brief Get the task status from an OMP GET_TASKS response.
 *
 * @param[in]  response   GET_TASKS response.
 *
 * @return The entity_text of the status entity if the entity is found, else
 *         NULL.
 */
const char*
omp_task_status (entity_t response)
{
  entity_t task = entity_child (response, "task");
  if (task)
    {
      entity_t status = entity_child (task, "status");
      if (status) return entity_text (status);
    }
  return NULL;
}

/**
 * @brief "Ping" the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  timeout   Server idle time before giving up, in milliseconds.  0
 *                       to wait forever.
 *
 * @return 0 on success, 1 if manager closed connection, 2 on timeout,
 *         -1 on error.
 */
int
omp_ping (gnutls_session_t *session, int timeout)
{
  entity_t entity;
  const char* status;
  char first;
  int ret;

  /* Send a GET_VERSION request. */

  ret = openvas_server_send (session, "<get_version/>");
  if (ret)
    return ret;

  /* Read the response, with a timeout. */

  entity = NULL;
  switch (try_read_entity (session, timeout, &entity))
    {
      case 0:
        break;
      case -4:
        return 2;
      default:
        return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  free_entity (entity);
  if (first == '2') return 0;
  return -1;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  username  Username.
 * @param[in]  password  Password.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         -1 on error.
 */
int
omp_authenticate (gnutls_session_t* session,
                  const char* username,
                  const char* password)
{
  entity_t entity;
  const char* status;
  char first;
  gchar* msg;

  /* Send the auth request. */

  msg = g_markup_printf_escaped ("<authenticate><credentials>"
                                 "<username>%s</username>"
                                 "<password>%s</password>"
                                 "</credentials></authenticate>",
                                 username,
                                 password);
  int ret = openvas_server_send (session, msg);
  g_free (msg);
  if (ret) return ret;

  /* Read the response. */

  entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  free_entity (entity);
  if (first == '2') return 0;
  return 2;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  username  Username.
 * @param[in]  password  Password.
 * @param[out] role      Role.
 * @param[out] timezone  Timezone if any, else NULL.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         -1 on error.
 */
int
omp_authenticate_info (gnutls_session_t *session,
                       const char *username,
                       const char *password,
                       char **role,
                       char **severity,
                       char **timezone)
{
  entity_t entity;
  const char* status;
  char first;
  gchar* msg;

  *timezone = NULL;

  /* Send the auth request. */

  msg = g_markup_printf_escaped ("<authenticate><credentials>"
                                 "<username>%s</username>"
                                 "<password>%s</password>"
                                 "</credentials></authenticate>",
                                 username,
                                 password);
  int ret = openvas_server_send (session, msg);
  g_free (msg);
  if (ret) return ret;

  /* Read the response. */

  entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first == '2')
    {
      entity_t timezone_entity, role_entity, severity_entity;
      /* Get the extra info. */
      timezone_entity = entity_child (entity, "timezone");
      if (timezone_entity)
        *timezone = g_strdup (entity_text (timezone_entity));
      role_entity = entity_child (entity, "role");
      if (role_entity)
        *role = g_strdup (entity_text (role_entity));
      severity_entity = entity_child (entity, "severity");
      if (severity_entity)
        *severity = g_strdup (entity_text (severity_entity));
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 2;
}

/**
 * @brief Create a task.
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of create_task request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out]  id       Pointer for newly allocated ID of new task, or NULL.
 *                       Only set on successful return.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_create_task_ext (gnutls_session_t* session,
                     omp_create_task_opts_t opts,
                     gchar** id)
{
  /* Create the OMP request. */

  gchar *new, *prefs, *start, *hosts_ordering, *schedule, *slave;
  GString *alerts, *observers;

  if ((opts.config_id == NULL) || (opts.target_id == NULL))
    return -1;

  prefs = NULL;
  start = g_markup_printf_escaped ("<create_task>"
                                   "<config id=\"%s\"/>"
                                   "<target id=\"%s\"/>"
                                   "<name>%s</name>"
                                   "<comment>%s</comment>"
                                   "<alterable>%d</alterable>",
                                   opts.config_id,
                                   opts.target_id,
                                   opts.name ? opts.name : "unnamed",
                                   opts.comment ? opts.comment : "",
                                   opts.alterable ? 1 : 0);

  if (opts.hosts_ordering)
    hosts_ordering = g_strdup_printf ("<hosts_ordering>%s</hosts_ordering>",
                                      opts.hosts_ordering);
  else
    hosts_ordering = NULL;

  if (opts.schedule_id)
    schedule = g_strdup_printf ("<schedule id=\"%s\"/>",
                                opts.schedule_id);
  else
    schedule = NULL;

  if (opts.slave_id)
    slave = g_strdup_printf ("<slave id=\"%s\"/>",
                             opts.slave_id);
  else
    slave = NULL;

  if (opts.max_checks || opts.max_hosts || opts.in_assets || opts.source_iface)
    {
      gchar *in_assets, *checks, *hosts, *source_iface;

      in_assets = checks = hosts = source_iface = NULL;

      if (opts.in_assets)
        in_assets = g_markup_printf_escaped ("<preference>"
                                             "<scanner_name>"
                                             "in_assets"
                                             "</scanner_name>"
                                             "<value>"
                                             "%s"
                                             "</value>"
                                             "</preference>",
                                             opts.in_assets);

      if (opts.max_checks)
        checks = g_markup_printf_escaped ("<preference>"
                                          "<scanner_name>"
                                          "max_hosts"
                                          "</scanner_name>"
                                          "<value>"
                                          "%s"
                                          "</value>"
                                          "</preference>",
                                          opts.max_hosts);

      if (opts.max_checks)
        hosts = g_markup_printf_escaped ("<preference>"
                                         "<scanner_name>"
                                         "max_checks"
                                         "</scanner_name>"
                                         "<value>"
                                         "%s"
                                         "</value>"
                                         "</preference>",
                                         opts.max_checks);

      if (opts.source_iface)
        source_iface = g_markup_printf_escaped ("<preference>"
                                                "<scanner_name>"
                                                "source_iface"
                                                "</scanner_name>"
                                                "<value>"
                                                "%s"
                                                "</value>"
                                                "</preference>",
                                                opts.source_iface);

      prefs = g_strdup_printf ("<preferences>%s%s%s%s</preferences>",
                               in_assets ? in_assets : "",
                               checks ? checks : "",
                               hosts ? hosts : "",
                               source_iface ? source_iface : "");
      g_free (in_assets);
      g_free (checks);
      g_free (hosts);
      g_free (source_iface);
    }

  if (opts.alert_ids)
    {
      int i;
      alerts = g_string_new ("");
      for (i = 0; i < opts.alert_ids->len; i++)
        {
          char *alert = (char*)g_ptr_array_index (opts.alert_ids, i);
          g_string_append_printf (alerts,
                                  "<alert id=\"%s\"/>",
                                  alert);
        }
    }
  else
    alerts = g_string_new ("");


  if (opts.observers || opts.observer_groups)
    {
      observers = g_string_new ("<observers>");

      if (opts.observers)
        g_string_append (observers, opts.observers);

      if (opts.observer_groups)
        {
          int i;
          for (i = 0; i < opts.observer_groups->len; i++)
            {
              char *group = (char*) g_ptr_array_index (opts.observer_groups, i);
              g_string_append_printf (observers,
                                      "<group id=\"%s\"/>",
                                      group);
            }
        }
      g_string_append (observers, "</observers>");
    }
  else
    observers = g_string_new ("");

  new = g_strdup_printf ("%s%s%s%s%s%s%s</create_task>",
                         start,
                         prefs ? prefs : "",
                         hosts_ordering ? hosts_ordering : "",
                         schedule ? schedule : "",
                         slave ? slave : "",
                         alerts ? alerts->str : "",
                         observers ? observers->str : "");
  g_free (start);
  g_free (prefs);
  g_free (hosts_ordering);
  g_free (schedule);
  g_free (slave);
  g_string_free (alerts, TRUE);
  g_string_free (observers, TRUE);

  /* Send the request. */

  int ret = openvas_server_send (session, new);
  g_free (new);
  if (ret) return -1;

  /* Read the response. */

  ret = omp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create a task given a config and target.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   name        Task name.
 * @param[in]   config      Task config name.
 * @param[in]   target      Task target name.
 * @param[in]   comment     Task comment.
 * @param[out]  id          Pointer for newly allocated ID of new task.  Only
 *                          set on successful return.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_create_task (gnutls_session_t* session,
                 const char* name,
                 const char* config,
                 const char* target,
                 const char* comment,
                 gchar** id)
{
  /* Create the OMP request. */

  gchar* new_task_request;
  new_task_request = g_markup_printf_escaped ("<create_task>"
                                              "<config id=\"%s\"/>"
                                              "<target id=\"%s\"/>"
                                              "<name>%s</name>"
                                              "<comment>%s</comment>"
                                              "</create_task>",
                                              config,
                                              target,
                                              name,
                                              comment);

  /* Send the request. */

  int ret = openvas_server_send (session, new_task_request);
  g_free (new_task_request);
  if (ret) return -1;

  /* Read the response. */

  ret = omp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create a task, given the task description as an RC file.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   config      Task configuration.
 * @param[in]   config_len  Length of config.
 * @param[in]   name        Task name.
 * @param[in]   comment     Task comment.
 * @param[out]  id          Pointer for newly allocated ID of new task.  Only
 *                          set on successful return.
 *
 * @return 0 on success, -1 on error.
 */
int
omp_create_task_rc (gnutls_session_t* session,
                    const char* config,
                    unsigned int config_len,
                    const char* name,
                    const char* comment,
                    char** id)
{
  /* Convert the file contents to base64. */

  gchar* new_task_file = strlen (config)
                         ? g_base64_encode ((guchar*) config, config_len)
                         : g_strdup ("");

  /* Create the OMP request. */

  gchar* new_task_request;
  new_task_request = g_markup_printf_escaped ("<create_task>"
                                              "<rcfile>%s</rcfile>"
                                              "<name>%s</name>"
                                              "<comment>%s</comment>"
                                              "</create_task>",
                                              new_task_file,
                                              name,
                                              comment);
  g_free (new_task_file);

  /* Send the request. */

  int ret = openvas_server_send (session, new_task_request);
  g_free (new_task_request);
  if (ret) return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Get the ID of the new task from the response. */

  entity_t id_entity = entity_child (entity, "task_id");
  if (id_entity == NULL)
    {
      free_entity (entity);
      return -1;
    }
  *id = g_strdup (entity_text (id_entity));
  return 0;
}

/**
 * @brief Start a task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 * @param[out]  report_id  ID of report.
 *
 * @return 0 on success, 1 on failure, -1 on error.
 */
int
omp_start_task_report (gnutls_session_t* session, const char* task_id,
                       char** report_id)
{
  if (openvas_server_sendf (session,
                            "<start_task task_id=\"%s\"/>",
                            task_id)
      == -1)
    return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  const char* status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  char first = status[0];
  if (first == '2')
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 1;
}

/**
 * @brief Resume or start a task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 * @param[out]  report_id  ID of report.
 *
 * @return 0 on success, 1 on failure, -1 on error.
 */
int
omp_resume_or_start_task_report (gnutls_session_t* session, const char* task_id,
                                 char** report_id)
{
  if (openvas_server_sendf (session,
                            "<resume_or_start_task task_id=\"%s\"/>",
                            task_id)
      == -1)
    return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  const char* status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  char first = status[0];
  if (first == '2')
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 1;
}

/**
 * @brief Resume or start a task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 *
 * @return 0 on success, 1 on failure, -1 on error.
 */
int
omp_resume_or_start_task (gnutls_session_t* session, const char* task_id)
{
  return omp_resume_or_start_task_report (session, task_id, NULL);
}

/** @todo Use this in the other functions. */
/**
 * @brief Read response and convert status of response to a return value.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
check_response (gnutls_session_t* session)
{
  int ret;
  const char* status;
  entity_t entity;

  /* Read the response. */

  entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  if (status[0] == '2')
    {
      free_entity (entity);
      return 0;
    }
  ret = (int) strtol (status, NULL, 10);
  free_entity (entity);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Read response status and resource UUID.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[out] uuid     Either NULL or address for freshly allocated UUID of
 *                      created response.
 *
 * @return OMP response code on success, -1 on error.
 */
int
omp_read_create_response (gnutls_session_t* session, gchar **uuid)
{
  int ret;
  const char *status, *id;
  entity_t entity;

  /* Read the response. */

  entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Parse the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }

  if (uuid)
    {
      id = entity_attribute (entity, "id");
      if (id == NULL)
        {
          free_entity (entity);
          return -1;
        }
      if (strlen (id) == 0)
        {
          free_entity (entity);
          return -1;
        }
      *uuid = g_strdup (id);
    }

  ret = atoi (status);
  free_entity (entity);
  return ret;
}

/**
 * @brief Stop a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, OMP response code on failure, -1 on error.
 */
int
omp_stop_task (gnutls_session_t* session, const char* id)
{
  if (openvas_server_sendf (session,
                            "<stop_task task_id=\"%s\"/>",
                            id)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Pause a task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 *
 * @return 0 on success, OMP response code on failure, -1 on error.
 */
int
omp_pause_task (gnutls_session_t* session, const char* task_id)
{
  if (openvas_server_sendf (session,
                            "<pause_task task_id=\"%s\"/>",
                            task_id)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Resume a paused task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 *
 * @return 0 on success, OMP response code on failure, -1 on error.
 */
int
omp_resume_paused_task (gnutls_session_t* session, const char* task_id)
{
  if (openvas_server_sendf (session,
                            "<resume_paused_task task_id=\"%s\"/>",
                            task_id)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Resume a stopped task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 * @param[out]  report_id  ID of report.
 *
 * @return 0 on success, 1 on OMP failure, -1 on error.
 */
int
omp_resume_stopped_task_report (gnutls_session_t* session, const char* task_id,
                                char** report_id)
{
  if (openvas_server_sendf (session,
                            "<resume_stopped_task task_id=\"%s\"/>",
                            task_id)
      == -1)
    return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (session, &entity)) return -1;

  /* Check the response. */

  const char* status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  char first = status[0];
  if (first == '2')
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 1;
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  id        ID of task.
 * @param[in]  opts      Struct containing the options to apply.
 *
 * @return 0 on success, OMP response code on failure, -1 on error.
 */
int
omp_delete_task_ext (gnutls_session_t* session, const char* id,
                     omp_delete_opts_t opts)
{
  if (openvas_server_sendf (session,
                            "<delete_task task_id=\"%s\" ultimate=\"%d\"/>",
                            id, opts.ultimate)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Get the status of a task.
 *
 * @param[in]  session         Pointer to GNUTLS session.
 * @param[in]  id              ID of task or NULL for all tasks.
 * @param[in]  details         Whether to request task details.
 * @param[in]  include_rcfile  Request rcfile in status if true.
 * @param[out] status          Status return.  On success contains GET_TASKS
 *                             response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_tasks (gnutls_session_t* session, const char* id, int details,
               int include_rcfile, entity_t* status)
{
  const char* status_code;
  int ret;

  if (id == NULL)
    {
      if (openvas_server_sendf (session,
                                "<get_tasks details=\"%i\" rcfile=\"%i\"/>",
                                details,
                                include_rcfile)
          == -1)
        return -1;
    }
  else
    {
      if (openvas_server_sendf (session,
                                "<get_tasks"
                                " task_id=\"%s\""
                                " details=\"%i\""
                                " rcfile=\"%i\"/>",
                                id,
                                details,
                                include_rcfile)
          == -1)
        return -1;
    }

  /* Read the response. */

  *status = NULL;
  if (read_entity (session, status)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*status, "status");
  if (status_code == NULL)
    {
      free_entity (*status);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*status);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*status);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Get a task (generic version).
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Task.  On success contains GET_TASKS response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_task_ext (gnutls_session_t* session,
                  omp_get_task_opts_t opts,
                  entity_t* response)
{
  int ret;
  const char *status_code;

  if ((response == NULL) || (opts.task_id == NULL))
    return -1;

  if (opts.actions)
    {
      if (openvas_server_sendf (session,
                                "<get_tasks"
                                " task_id=\"%s\""
                                " actions=\"%s\""
                                "%s%s/>",
                                opts.task_id,
                                opts.actions,
                                OMP_FMT_BOOL_ATTRIB (opts, details),
                                OMP_FMT_BOOL_ATTRIB (opts, rcfile)))
        return -1;
    }
  else if (openvas_server_sendf (session,
                                 "<get_tasks"
                                 " task_id=\"%s\""
                                 "%s%s/>",
                                 opts.task_id,
                                 OMP_FMT_BOOL_ATTRIB (opts, details),
                                 OMP_FMT_BOOL_ATTRIB (opts, rcfile)))
    return -1;

  *response = NULL;
  if (read_entity (session, response)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Get all tasks (generic version).
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Tasks.  On success contains GET_TASKS response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_tasks_ext (gnutls_session_t* session,
                   omp_get_tasks_opts_t opts,
                   entity_t* response)
{
  int ret;
  const char *status_code;
  gchar *cmd;

  if (response == NULL)
    return -1;

  cmd = g_markup_printf_escaped ("<get_tasks"
                                 " filter=\"%s\"",
                                 opts.filter);

  if (openvas_server_sendf (session,
                            "%s%s%s/>",
                            cmd,
                            OMP_FMT_BOOL_ATTRIB (opts, details),
                            OMP_FMT_BOOL_ATTRIB (opts, rcfile)))
    {
      g_free (cmd);
      return -1;
    }
  g_free (cmd);

  *response = NULL;
  if (read_entity (session, response)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Modify a file on a task.
 *
 * @param[in]  session      Pointer to GNUTLS session.
 * @param[in]  id           ID of task.
 * @param[in]  name         Name of file.
 * @param[in]  content      New content.  NULL to remove file.
 * @param[in]  content_len  Length of content.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_modify_task_file (gnutls_session_t* session, const char* id,
                      const char* name, const void* content,
                      gsize content_len)
{
  if (name == NULL)
    return -1;

  if (openvas_server_sendf (session, "<modify_task task_id=\"%s\">", id))
    return -1;

  if (content)
    {
      if (openvas_server_sendf (session, "<file name=\"%s\" action=\"update\">",
                                name))
        return -1;

      if (content_len)
        {
          gchar *base64_rc = g_base64_encode ((guchar*) content,
                                              content_len);
          int ret = openvas_server_sendf (session,
                                          "%s",
                                          base64_rc);
          g_free (base64_rc);
          if (ret) return -1;
        }

      if (openvas_server_sendf (session, "</file>"))
        return -1;
    }
  else
    {
      if (openvas_server_sendf (session,
                                "<file name=\"%s\" action=\"remove\" />",
                                name))
        return -1;
    }

  if (openvas_server_send (session, "</modify_task>"))
    return -1;

  return check_response (session);
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, OMP response code on failure, -1 on error.
 */
int
omp_delete_task (gnutls_session_t* session, const char* id)
{
  if (openvas_server_sendf (session, "<delete_task task_id=\"%s\"/>", id) == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Get a target.
 *
 * @param[in]  session         Pointer to GNUTLS session.
 * @param[in]  id              ID of target or NULL for all targets.
 * @param[in]  tasks           Whether to include tasks that use the target.
 * @param[out] target          Target return.  On success contains GET_TARGETS
 *                             response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_targets (gnutls_session_t* session, const char* id, int tasks,
                 int include_rcfile, entity_t* target)
{
  const char* status_code;
  int ret;

  if (id == NULL)
    {
      if (openvas_server_sendf (session,
                                "<get_targets tasks=\"%i\"/>",
                                tasks)
          == -1)
        return -1;
    }
  else
    {
      if (openvas_server_sendf (session,
                                "<get_targets"
                                " target_id=\"%s\""
                                " tasks=\"%i\"/>",
                                id,
                                tasks)
          == -1)
        return -1;
    }

  /* Read the response. */

  *target = NULL;
  if (read_entity (session, target)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*target, "status");
  if (status_code == NULL)
    {
      free_entity (*target);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*target);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*target);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Get a report (generic version).
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of get_reports request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Report.  On success contains GET_REPORT response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_report_ext (gnutls_session_t* session,
                    omp_get_report_opts_t opts,
                    entity_t* response)
{
  int ret;
  const char *status_code;

  if (response == NULL)
    return -1;

  if (openvas_server_sendf (session,
                            "<get_reports"
                            " report_id=\"%s\""
                            " format_id=\"%s\""
                            " sort_field=\"%s\""
                            " sort_order=\"%s\""
                            " levels=\"%s\""
                            " first_result=\"%i\""
                            " max_results=\"%i\""
                            " host_first_result=\"%i\""
                            " host_max_results=\"%i\""
                            " autofp=\"%i\""
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s"
                            "%s%s%s%s%s%s/>",
                            opts.report_id,
                            opts.format_id,
                            opts.sort_field,
                            opts.sort_order,
                            opts.levels,
                            opts.first_result,
                            opts.max_results,
                            opts.host_first_result,
                            opts.host_max_results,
                            opts.autofp,
                            OMP_FMT_STRING_ATTRIB (opts, type),
                            OMP_FMT_STRING_ATTRIB (opts, host),
                            OMP_FMT_STRING_ATTRIB (opts, pos),
                            OMP_FMT_STRING_ATTRIB (opts, timezone),
                            OMP_FMT_STRING_ATTRIB (opts, alert_id),
                            OMP_FMT_STRING_ATTRIB (opts, delta_report_id),
                            OMP_FMT_STRING_ATTRIB (opts, delta_states),
                            OMP_FMT_STRING_ATTRIB (opts, host_levels),
                            OMP_FMT_STRING_ATTRIB (opts, search_phrase),
                            OMP_FMT_STRING_ATTRIB (opts, host_search_phrase),
                            OMP_FMT_STRING_ATTRIB (opts, min_cvss_base),
                            OMP_FMT_BOOL_ATTRIB (opts, notes),
                            OMP_FMT_BOOL_ATTRIB (opts, notes_details),
                            OMP_FMT_BOOL_ATTRIB (opts, overrides),
                            OMP_FMT_BOOL_ATTRIB (opts, override_details),
                            OMP_FMT_BOOL_ATTRIB (opts, apply_overrides),
                            OMP_FMT_BOOL_ATTRIB (opts, result_hosts_only)))
    return -1;

  *response = NULL;
  if (read_entity (session, response)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Remove a report.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  id        ID of report.
 *
 * @return 0 on success, OMP response code on failure, -1 on error.
 */
int
omp_delete_report (gnutls_session_t *session, const char *id)
{
  if (openvas_server_sendf (session, "<delete_report report_id=\"%s\"/>", id))
    return -1;

  return check_response (session);
}

/**
 * @brief Create a target.
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of create_target request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] id        Pointer for newly allocated ID of new target, or NULL.
 *                       Only set on successful return.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_create_target_ext (gnutls_session_t* session,
                       omp_create_target_opts_t opts,
                       gchar** id)
{
  gchar *new, *comment, *ssh, *smb, *port_range, *start;
  gchar *exclude_hosts, *alive_tests;

  /* Create the OMP request. */

  if (opts.hosts == NULL)
    return -1;

  start = g_markup_printf_escaped ("<create_target>"
                                   "<name>%s</name>"
                                   "<hosts>%s</hosts>",
                                   opts.name ? opts.name : "unnamed",
                                   opts.hosts);

  if (opts.exclude_hosts)
    exclude_hosts = g_markup_printf_escaped ("<exclude_hosts>"
                                             "%s"
                                             "</exclude_hosts>",
                                             opts.exclude_hosts);
  else
    exclude_hosts = NULL;

  if (opts.alive_tests)
    alive_tests = g_markup_printf_escaped ("<alive_tests>"
                                           "%s"
                                           "</alive_tests>",
                                           opts.alive_tests);
  else
    alive_tests = NULL;

  if (opts.comment)
    comment = g_markup_printf_escaped ("<comment>"
                                       "%s"
                                       "</comment>",
                                      opts.comment);
  else
    comment = NULL;

  if (opts.ssh_credential_id)
    {
      if (opts.ssh_credential_port)
        ssh = g_markup_printf_escaped ("<ssh_lsc_credential id=\"%s\">"
                                       "<port>%i</port>"
                                       "</ssh_lsc_credential>",
                                       opts.ssh_credential_id,
                                       opts.ssh_credential_port);
      else
        ssh = g_markup_printf_escaped ("<ssh_lsc_credential id=\"%s\"/>",
                                       opts.ssh_credential_id);
    }
  else
    ssh = NULL;

  if (opts.smb_credential_id)
    smb = g_markup_printf_escaped ("<smb_lsc_credential id=\"%s\"/>",
                                   opts.smb_credential_id);
  else
    smb = NULL;

  if (opts.port_range)
    port_range = g_markup_printf_escaped ("<port_range>%s</port_range>",
                                          opts.port_range);
  else
    port_range = NULL;

  new = g_strdup_printf ("%s%s%s%s%s%s%s"
                         "<reverse_lookup_only>%d</reverse_lookup_only>"
                         "<reverse_lookup_unify>%d</reverse_lookup_unify>"
                         "</create_target>",
                         start,
                         exclude_hosts ? exclude_hosts : "",
                         alive_tests ? alive_tests : "",
                         ssh ? ssh : "",
                         smb ? smb : "",
                         port_range ? port_range : "",
                         comment ? comment : "",
                         opts.reverse_lookup_only,
                         opts.reverse_lookup_unify);
  g_free (start);
  g_free (exclude_hosts);
  g_free (alive_tests);
  g_free (ssh);
  g_free (smb);
  g_free (port_range);
  g_free (comment);

  /* Send the request. */

  int ret = openvas_server_send (session, new);
  g_free (new);
  if (ret) return -1;

  /* Read the response. */

  ret = omp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Delete a target.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of target.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_delete_target_ext (gnutls_session_t* session,
                       const char* id,
                       omp_delete_opts_t opts)
{
  if (openvas_server_sendf (session,
                            "<delete_target target_id=\"%s\" ultimate=\"%d\"/>",
                            id, opts.ultimate)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Delete a config.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of config.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_delete_config_ext (gnutls_session_t* session,
                       const char* id,
                       omp_delete_opts_t opts)
{
  if (openvas_server_sendf (session,
                            "<delete_config config_id=\"%s\" ultimate=\"%d\"/>",
                            id, opts.ultimate)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Create an LSC Credential.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   name      Name of LSC Credential.
 * @param[in]   login     Login associated with name.
 * @param[in]   password  Password, or NULL for autogenerated credentials.
 * @param[in]   comment   LSC Credential comment.
 * @param[out]  uuid      Either NULL or address for UUID of created credential.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_create_lsc_credential (gnutls_session_t* session,
                           const char* name,
                           const char* login,
                           const char* password,
                           const char* comment,
                           gchar** uuid)
{
  int ret;

  /* Create the OMP request. */

  gchar* new_task_request;
  if (password)
    {
      if (comment)
        new_task_request = g_markup_printf_escaped ("<create_lsc_credential>"
                                                    "<name>%s</name>"
                                                    "<login>%s</login>"
                                                    "<password>%s</password>"
                                                    "<comment>%s</comment>"
                                                    "</create_lsc_credential>",
                                                    name,
                                                    login,
                                                    password,
                                                    comment);
      else
        new_task_request = g_markup_printf_escaped ("<create_lsc_credential>"
                                                    "<name>%s</name>"
                                                    "<login>%s</login>"
                                                    "<password>%s</password>"
                                                    "</create_lsc_credential>",
                                                    name,
                                                    login,
                                                    password);
    }
  else
    {
      if (comment)
        new_task_request = g_markup_printf_escaped ("<create_lsc_credential>"
                                                    "<name>%s</name>"
                                                    "<login>%s</login>"
                                                    "<comment>%s</comment>"
                                                    "</create_lsc_credential>",
                                                    name,
                                                    login,
                                                    comment);
      else
        new_task_request = g_markup_printf_escaped ("<create_lsc_credential>"
                                                    "<name>%s</name>"
                                                    "<login>%s</login>"
                                                    "</create_lsc_credential>",
                                                    name,
                                                    login);
    }

  /* Send the request. */

  ret = openvas_server_send (session, new_task_request);
  g_free (new_task_request);
  if (ret) return -1;

  ret = omp_read_create_response (session, uuid);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create an LSC Credential with a key.
 *
 * @param[in]   session      Pointer to GNUTLS session.
 * @param[in]   name         Name of LSC Credential.
 * @param[in]   login        Login associated with name.
 * @param[in]   passphrase   Passphrase for public key.
 * @param[in]   public_key   Public key.
 * @param[in]   private_key  Private key.
 * @param[in]   comment      LSC Credential comment.
 * @param[out]  uuid         Either NULL or address for UUID of created
 *                           credential.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_create_lsc_credential_key (gnutls_session_t *session,
                               const char *name,
                               const char *login,
                               const char *passphrase,
                               const char *public_key,
                               const char *private_key,
                               const char *comment,
                               gchar **uuid)
{
  int ret;

  /* Create the OMP request. */

  gchar* request;
  if (comment)
    request = g_markup_printf_escaped ("<create_lsc_credential>"
                                       "<name>%s</name>"
                                       "<login>%s</login>"
                                       "<key>"
                                       "<phrase>%s</phrase>"
                                       "<public>%s</public>"
                                       "<private>%s</private>"
                                       "</key>"
                                       "<comment>%s</comment>"
                                       "</create_lsc_credential>",
                                       name,
                                       login,
                                       passphrase
                                        ? passphrase
                                        : "",
                                       public_key,
                                       private_key,
                                       comment);
  else
    request = g_markup_printf_escaped ("<create_lsc_credential>"
                                       "<name>%s</name>"
                                       "<login>%s</login>"
                                       "<key>"
                                       "<phrase>%s</phrase>"
                                       "<public>%s</public>"
                                       "<private>%s</private>"
                                       "</key>"
                                       "</create_lsc_credential>",
                                       name,
                                       login,
                                       passphrase
                                        ? passphrase
                                        : "",
                                       public_key,
                                       private_key);

  /* Send the request. */

  ret = openvas_server_send (session, request);
  g_free (request);
  if (ret) return -1;

  ret = omp_read_create_response (session, uuid);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Delete a LSC credential.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   uuid        UUID of LSC credential.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_delete_lsc_credential_ext (gnutls_session_t* session,
                               const char* id,
                               omp_delete_opts_t opts)
{
  if (openvas_server_sendf (session,
                            "<delete_lsc_credential lsc_credential_id=\"%s\""
                            " ultimate=\"%d\"/>",
                            id, opts.ultimate)
      == -1)
    return -1;

  return check_response (session);
}

/**
 * @brief Get system reports.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  name     Name of system report.  NULL for all.
 * @param[in]  brief    Whether to request brief response.
 * @param[out] reports  Reports return.  On success contains GET_SYSTEM_REPORTS
 *                      response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_system_reports (gnutls_session_t* session, const char* name, int brief,
                        entity_t *reports)
{
  int ret;
  const char *status_code;

  if (name)
    {
      if (openvas_server_sendf (session,
                                "<get_system_reports name=\"%s\" brief=\"%i\"/>",
                                name,
                                brief)
          == -1)
        return -1;
    }
  else if (openvas_server_sendf (session,
                                 "<get_system_reports brief=\"%i\"/>",
                                 brief)
           == -1)
    return -1;

  /* Read the response. */

  *reports = NULL;
  if (read_entity (session, reports)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*reports, "status");
  if (status_code == NULL)
    {
      free_entity (*reports);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*reports);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*reports);
  if (errno == ERANGE) return -1;
  return ret;
}

/**
 * @brief Get system reports.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  opts     Struct containing the options to apply.
 * @param[out] reports  Reports return.  On success contains GET_SYSTEM_REPORTS
 *                      response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
omp_get_system_reports_ext (gnutls_session_t* session,
                            omp_get_system_reports_opts_t opts,
                            entity_t *reports)
{
  const char* status_code;
  gchar *slave_id_attrib;
  int ret;

  slave_id_attrib = opts.slave_id ? g_strdup_printf (" slave_id=\"%s\"",
                                                     opts.slave_id)
                                  : g_strdup ("");

  /* Create the OMP request. */

  if (opts.name && opts.duration)
    {
      if (openvas_server_sendf (session,
                                "<get_system_reports%s"
                                " name=\"%s\""
                                " duration=\"%s\""
                                " brief=\"%i\"/>",
                                slave_id_attrib,
                                opts.name,
                                opts.duration,
                                opts.brief)
          == -1)
        {
          g_free (slave_id_attrib);
          return -1;
        }
    }
  else if (opts.name)
    {
      if (openvas_server_sendf (session,
                                "<get_system_reports%s"
                                " name=\"%s\""
                                " brief=\"%i\"/>",
                                slave_id_attrib,
                                opts.name,
                                opts.brief)
          == -1)
        {
          g_free (slave_id_attrib);
          return -1;
        }
    }
  else if (opts.duration)
    {
      if (openvas_server_sendf (session,
                                "<get_system_reports%s"
                                " duration=\"%s\""
                                " brief=\"%i\"/>",
                                slave_id_attrib,
                                opts.duration,
                                opts.brief)
          == -1)
        {
          g_free (slave_id_attrib);
          return -1;
        }
    }
  else if (openvas_server_sendf (session,
                                 "<get_system_reports%s brief=\"%i\"/>",
                                 slave_id_attrib,
                                 opts.brief)
           == -1)
    {
      g_free (slave_id_attrib);
      return -1;
    }

  /* Read the response. */

  *reports = NULL;
  if (read_entity (session, reports)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*reports, "status");
  if (status_code == NULL)
    {
      free_entity (*reports);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*reports);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*reports);
  if (errno == ERANGE) return -1;
  return ret;
}
