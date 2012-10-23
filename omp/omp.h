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
 *
 * FIXME: This SHOULD contain all valid options from the OMP spec.
 */
typedef struct
{
  const char* sort_field;
  const char* sort_order;
  const char* format_id;   ///< ID of required report format.
  const char* report_id;   ///< ID of single report to get.
  int first_result;        ///< First result to get.
  /* Boolean flags: */
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
    "ROWID", "ascending", "a994b278-1f62-11e1-96ac-406186ea4fc5"
  };

/**
 * @brief Struct holding options for omp create_task command.
 *
 * FIXME: This SHOULD contain all valid options from the OMP spec.
 */
typedef struct
{
  const char* config_id;   ///< ID of config.
  const char* target_id;   ///< ID of target.
  const char* name;        ///< Name of task.
  const char* comment;     ///< Comment on task.
  const char* max_hosts;   ///< Max hosts preference.
  const char* max_checks;  ///< Max checks preference.
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
  const char* ssh_credential_id;   ///< ID of SSH credential.
  const char* smb_credential_id;   ///< ID of SMB credential.
  const char* port_range;          ///< Port range.
  const char* name;                ///< Name of target.
  const char* comment;             ///< Comment on target.
  const char* hosts;               ///< Name of target.
} omp_create_target_opts_t;

/**
 * @brief Sensible default values for omp_get_report_opts_t.
 */
static const omp_create_target_opts_t omp_create_target_opts_defaults =
  { };

int check_response (gnutls_session_t *);

int omp_read_create_response (gnutls_session_t*, gchar **);

const char *omp_task_status (entity_t status_response);

int omp_ping (gnutls_session_t *, int);

int omp_get_nvt_all (gnutls_session_t * session, entity_t * response);

int omp_get_nvt_feed_checksum (gnutls_session_t * session, entity_t * response);

int omp_get_dependencies_503 (gnutls_session_t * session, entity_t * response);

int omp_authenticate (gnutls_session_t * session, const char *username,
                      const char *password);

int omp_authenticate_info (gnutls_session_t * session, const char *username,
                           const char *, char **, char **);

int omp_authenticate_env (gnutls_session_t * session);

int omp_create_task_rc (gnutls_session_t *, const char *, unsigned int,
                        const char *, const char *, char **);

int omp_create_task (gnutls_session_t *, const char *, const char *,
                     const char *, const char *, gchar **);

int omp_create_task_ext (gnutls_session_t *, omp_create_task_opts_t, gchar **);

int omp_create_task_rc_file (gnutls_session_t *, const char *, const char *,
                             const char *, char **);

int omp_start_task_report (gnutls_session_t *, const char *, char **);

int omp_start_task (gnutls_session_t *, const char *);

int omp_resume_or_start_task_report (gnutls_session_t *, const char *, char **);

int omp_resume_or_start_task (gnutls_session_t *, const char *);

int omp_abort_task (gnutls_session_t *, const char *);

int omp_stop_task (gnutls_session_t *, const char *);

int omp_pause_task (gnutls_session_t*, const char*);

int omp_resume_paused_task (gnutls_session_t*, const char*);

int omp_resume_stopped_task (gnutls_session_t*, const char*);

int omp_resume_stopped_task_report (gnutls_session_t*, const char*, char**);

int omp_wait_for_task_end (gnutls_session_t *, const char *);

int omp_wait_for_task_start (gnutls_session_t *, const char *);

int omp_wait_for_task_stop (gnutls_session_t *, const char *);

int omp_wait_for_task_delete (gnutls_session_t *, const char *);

int omp_get_status (gnutls_session_t *, const char *, int, entity_t *);

int omp_get_tasks (gnutls_session_t *, const char *, int, int, entity_t *);

int omp_get_targets (gnutls_session_t *, const char *, int, int, entity_t *);

int omp_get_report (gnutls_session_t *, const char *, const char *,
                    int, entity_t *);
int omp_get_report_ext (gnutls_session_t *, omp_get_report_opts_t, entity_t *);

int omp_get_report_format (gnutls_session_t *, const char *, const char *,
                           void **, gsize *);

int omp_delete_report (gnutls_session_t *, const char *);

int omp_get_results (gnutls_session_t *, const char *, int, int, int, int, int,
                     entity_t *);

int omp_delete_task (gnutls_session_t *, const char *);

int omp_modify_task (gnutls_session_t *, const char *, const char *,
                     const char *, const char *);

int omp_modify_task_file (gnutls_session_t *, const char *, const char *,
                          const void *, gsize);

int omp_get_preferences (gnutls_session_t *, entity_t *);

int omp_get_preferences_503 (gnutls_session_t *, entity_t *);

int omp_get_certificates (gnutls_session_t *, entity_t *);

int omp_until_up (int (*)(gnutls_session_t *, entity_t *), gnutls_session_t *,
                  entity_t *);

int omp_create_target (gnutls_session_t *, const char *, const char *,
                       const char *, const char *, const char *, gchar **);

int omp_create_target_ext (gnutls_session_t *, omp_create_target_opts_t,
                           gchar**);

int omp_delete_target (gnutls_session_t *, const char *);

int omp_create_config (gnutls_session_t *, const char *, const char *,
                       const char *, unsigned int);

int omp_create_config_from_rc_file (gnutls_session_t *, const char *,
                                    const char *, const char *);

int omp_delete_config (gnutls_session_t *, const char *);

int omp_create_lsc_credential (gnutls_session_t *, const char *, const char *,
                               const char *, const char *, gchar **);

int omp_create_lsc_credential_key (gnutls_session_t *, const char *,
                                   const char *, const char *, const char *,
                                   const char *, const char *, gchar **);

int omp_delete_lsc_credential (gnutls_session_t *, const char *);

int omp_create_agent (gnutls_session_t *, const char *, const char *);

int omp_delete_agent (gnutls_session_t *, const char *);

int omp_get_nvt_details_503 (gnutls_session_t *, const char *, entity_t *);

int omp_get_system_reports (gnutls_session_t *, const char *, int, entity_t *);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* not _OPENVAS_LIBRARIES_OMP_H */
