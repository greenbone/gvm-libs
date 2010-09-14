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

int check_response (gnutls_session_t *);

int omp_read_create_response (gnutls_session_t*, char **);

const char *omp_task_status (entity_t status_response);

int omp_get_nvt_all (gnutls_session_t * session, entity_t * response);

int omp_get_nvt_feed_checksum (gnutls_session_t * session, entity_t * response);

int omp_get_dependencies_503 (gnutls_session_t * session, entity_t * response);

int omp_authenticate (gnutls_session_t * session, const char *username,
                      const char *password);

int omp_authenticate_env (gnutls_session_t * session);

int omp_create_task_rc (gnutls_session_t *, const char *, unsigned int,
                        const char *, const char *, char **);

int omp_create_task (gnutls_session_t *, const char *, const char *,
                     const char *, const char *, char **);

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

int omp_get_report (gnutls_session_t *, const char *, const char *, int, entity_t *);

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
                       const char *, const char *, char **);

int omp_delete_target (gnutls_session_t *, const char *);

int omp_create_config (gnutls_session_t *, const char *, const char *,
                       const char *, unsigned int);

int omp_create_config_from_rc_file (gnutls_session_t *, const char *,
                                    const char *, const char *);

int omp_delete_config (gnutls_session_t *, const char *);

int omp_create_lsc_credential (gnutls_session_t *, const char *, const char *,
                               const char *, const char *, char **);

int omp_delete_lsc_credential (gnutls_session_t *, const char *);

int omp_create_agent (gnutls_session_t *, const char *, const char *);

int omp_delete_agent (gnutls_session_t *, const char *);

int omp_get_nvt_details_503 (gnutls_session_t *, const char *, entity_t *);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* not _OPENVAS_LIBRARIES_OMP_H */
