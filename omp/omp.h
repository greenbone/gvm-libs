/* openvase-libraries/omp
 * $Id$
 * Description: Header for OMP client interface.
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

#ifndef _OPENVAS_LIBRARIES_OMP_H
#define _OPENVAS_LIBRARIES_OMP_H

#include "../base/array.h"
#include "xml.h"

#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif

/**
 * @brief Struct holding options for omp get_report command.
 */
typedef struct
{
  const char* sort_field;
  const char* sort_order;
  const char* format_id;   ///< ID of required report format.
  const char* levels;      ///< Result levels to include.
  const char* report_id;   ///< ID of single report to get.
  int first_result;        ///< First result to get.
  int max_results;         ///< Maximum number of results to return.
  int host_first_result;   ///< Skip over results before this result number.
  int host_max_results;    ///< Maximum number of results to return.
  int autofp;              ///< Whether to trust vendor security updates. 0 No, 1 full match, 2 partial.
  char *type;              ///< Type of report.
  char *host;              ///< Host for asset report.
  char *pos;               ///< Position of report from end.
  char *timezone;          ///< Timezone.
  char *alert_id;          ///< ID of alert.
  char *delta_report_id;   ///< ID of report to compare single report to.
  char *delta_states;      ///< Delta states (Changed Gone New Same) to include.
  char *host_levels;       ///< Letter encoded threat level filter, for hosts.
  char *search_phrase;     ///< Search phrase result filter.
  char *host_search_phrase;///< Search phrase result filter.
  char *min_cvss_base;     ///< Minimum CVSS base filter.
  /* Boolean flags: */
  int notes;               ///< Whether to include associated notes.
  int notes_details;       ///< Whether to include details of above.
  int overrides;           ///< Whether to include overrides in the report.
  int override_details;    ///< If overrides, whether to include details.
  int apply_overrides;     ///< Whether overrides are applied.
  int result_hosts_only;   ///< Whether to include only hosts that have results.
} omp_get_report_opts_t;

/**
 * @brief Sensible default values for omp_get_report_opts_t.
 */
static const omp_get_report_opts_t omp_get_report_opts_defaults =
  {
    "ROWID", "ascending", "a994b278-1f62-11e1-96ac-406186ea4fc5", "hmlgd",
    NULL, 1, -1
  };

/**
 * @brief Struct holding options for omp get_tasks command.
 */
typedef struct
{
  const char* filter;    ///< Filter argument.
  const char* actions;   ///< Actions argument.
  /* Boolean flags: */
  int details;           ///< Whether to include overrides in the tasks.
  int rcfile;            ///< If overrides, whether to include details.
} omp_get_tasks_opts_t;

/**
 * @brief Sensible default values for omp_get_tasks_opts_t.
 */
static const omp_get_tasks_opts_t omp_get_tasks_opts_defaults =
  { "" };

/**
 * @brief Struct holding options for omp get_tasks command.
 */
typedef struct
{
  const char* actions;   ///< Actions argument.
  const char* task_id;   ///< ID of single task to get.
  /* Boolean flags: */
  int details;           ///< Whether to include overrides in the tasks.
  int rcfile;            ///< If overrides, whether to include details.
} omp_get_task_opts_t;

/**
 * @brief Sensible default values for omp_get_tasks_opts_t.
 */
static const omp_get_task_opts_t omp_get_task_opts_defaults =
  { };

/**
 * @brief Struct holding options for omp create_task command.
 */
typedef struct
{
  array_t*    alert_ids;      ///< Array of alert IDs.
  const char* config_id;      ///< ID of config.
  const char* schedule_id;    ///< ID of task schedule.
  const char* slave_id;       ///< ID of task schedule.
  const char* target_id;      ///< ID of target.
  const char* name;           ///< Name of task.
  const char* comment;        ///< Comment on task.
  const char* hosts_ordering; ///< Order for scanning target hosts.
  const char* observers;      ///< Comma-separated string of observer users.
  array_t*    observer_groups;///< IDs of observer groups.
  /* Preferences */
  const char* in_assets;      ///< In assets preference.
  const char* max_hosts;      ///< Max hosts preference.
  const char* max_checks;     ///< Max checks preference.
  const char* source_iface;   ///< Source iface preference.
  /* Boolean flags: */
  int alterable;              ///< Whether the task is alterable.
} omp_create_task_opts_t;

/**
 * @brief Sensible default values for omp_get_report_opts_t.
 */
static const omp_create_task_opts_t omp_create_task_opts_defaults =
  { };

/**
 * @brief Struct holding options for omp create_target command.
 */
typedef struct
{
  int ssh_credential_port;         ///< Port for SSH access.
  const char* ssh_credential_id;   ///< ID of SSH credential.
  const char* smb_credential_id;   ///< ID of SMB credential.
  const char* port_range;          ///< Port range.
  const char* name;                ///< Name of target.
  const char* comment;             ///< Comment on target.
  const char* hosts;               ///< Name of target.
  const char* exclude_hosts;       ///< Hosts to exclude.
  const char* alive_tests;         ///< Alive tests.
  /* Boolean flags: */
  int reverse_lookup_only;         ///< Scanner pref reverse_lookup_only.
  int reverse_lookup_unify;        ///< Scanner pref reverse_lookup_unify.
} omp_create_target_opts_t;

/**
 * @brief Sensible default values for omp_get_report_opts_t.
 */
static const omp_create_target_opts_t omp_create_target_opts_defaults =
  { 0 };

/**
 * @brief Struct holding options for omp get_system_reports command.
 */
typedef struct
{
  const char* name;                ///< Name of report.
  const char* duration;            ///< Duration.
  const char* slave_id;            ///< ID of the slave to get report from.
  int brief;                       ///< Brief flag.
} omp_get_system_reports_opts_t;

/**
 * @brief Sensible default values for omp_get_report_opts_t.
 */
static const omp_get_system_reports_opts_t omp_get_system_reports_opts_defaults =
  { };

/**
 * @brief Struct holding options for various omp delete_[...] commands.
 */
typedef struct
{
  int ultimate; /// Whether to delete ultimately.
} omp_delete_opts_t;

/**
 * @brief Sensible default values for omp_get_report_opts_t.
 */
static const omp_delete_opts_t omp_delete_opts_defaults =
  { 0 };

/**
 * @brief Default values for omp_get_report_opts_t for ultimate deletion.
 */
static const omp_delete_opts_t omp_delete_opts_ultimate_defaults =
  { 1 };

int check_response (gnutls_session_t *);

int omp_read_create_response (gnutls_session_t*, gchar **);

const char *omp_task_status (entity_t status_response);

int omp_ping (gnutls_session_t *, int);

int omp_authenticate (gnutls_session_t * session, const char *username,
                      const char *password);

int omp_authenticate_info (gnutls_session_t * session, const char *username,
                           const char *, char **, char **, char **);

int omp_create_task_rc (gnutls_session_t *, const char *, unsigned int,
                        const char *, const char *, char **);

int omp_create_task (gnutls_session_t *, const char *, const char *,
                     const char *, const char *, gchar **);

int omp_create_task_ext (gnutls_session_t *, omp_create_task_opts_t, gchar **);

int omp_start_task_report (gnutls_session_t *, const char *, char **);

int omp_resume_or_start_task_report (gnutls_session_t *, const char *, char **);

int omp_resume_or_start_task (gnutls_session_t *, const char *);

int omp_stop_task (gnutls_session_t *, const char *);

int omp_pause_task (gnutls_session_t*, const char*);

int omp_resume_paused_task (gnutls_session_t*, const char*);

int omp_resume_stopped_task_report (gnutls_session_t*, const char*, char**);

int omp_get_tasks (gnutls_session_t *, const char *, int, int, entity_t *);

int omp_get_tasks_ext (gnutls_session_t *, omp_get_tasks_opts_t, entity_t *);

int omp_get_task_ext (gnutls_session_t *, omp_get_task_opts_t, entity_t *);

int omp_get_targets (gnutls_session_t *, const char *, int, int, entity_t *);

int omp_get_report_ext (gnutls_session_t *, omp_get_report_opts_t, entity_t *);

int omp_delete_task (gnutls_session_t *, const char *);

int omp_delete_task_ext (gnutls_session_t *, const char *, omp_delete_opts_t);

int omp_modify_task_file (gnutls_session_t *, const char *, const char *,
                          const void *, gsize);

int omp_delete_report (gnutls_session_t*, const char*);

int omp_create_target_ext (gnutls_session_t *, omp_create_target_opts_t,
                           gchar**);

int omp_delete_target_ext (gnutls_session_t *, const char *, omp_delete_opts_t);

int omp_delete_config_ext (gnutls_session_t *, const char *, omp_delete_opts_t);

int omp_create_lsc_credential (gnutls_session_t *, const char *, const char *,
                               const char *, const char *, gchar **);

int omp_create_lsc_credential_key (gnutls_session_t *, const char *,
                                   const char *, const char *, const char *,
                                   const char *, const char *, gchar **);

int omp_delete_lsc_credential_ext (gnutls_session_t *, const char *,
                                   omp_delete_opts_t);

int omp_get_system_reports (gnutls_session_t *, const char *, int, entity_t *);

int omp_get_system_reports_ext (gnutls_session_t *,
                                omp_get_system_reports_opts_t,
                                entity_t *);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* not _OPENVAS_LIBRARIES_OMP_H */
