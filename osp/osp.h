/* Copyright (C) 2014-2019 Greenbone Networks GmbH
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

#ifndef _GVM_OSP_H
#define _GVM_OSP_H

#include <glib.h> /* for GHashTable, GSList */
#include "../util/xmlutils.h"

/* Type definitions */

typedef struct osp_connection osp_connection_t;

typedef struct osp_credential osp_credential_t;

typedef struct osp_target osp_target_t;

typedef struct osp_vt_group osp_vt_group_t;

typedef struct osp_vt_single osp_vt_single_t;

/**
 * @brief OSP parameter types.
 */
typedef enum
{
  OSP_PARAM_TYPE_INT = 0,      /**< Integer type. */
  OSP_PARAM_TYPE_STR,          /**< String type. */
  OSP_PARAM_TYPE_PASSWORD,     /**< Password type. */
  OSP_PARAM_TYPE_FILE,         /**< File type. */
  OSP_PARAM_TYPE_BOOLEAN,      /**< Boolean type. */
  OSP_PARAM_TYPE_OVALDEF_FILE, /**< Oval definition type. */
  OSP_PARAM_TYPE_SELECTION,    /**< Selection type. */
  OSP_PARAM_TYPE_CRD_UP,       /**< Credential user/pass type. */
} osp_param_type_t;

/**
 * @brief OSP scan status.
 */
typedef enum
{
  OSP_SCAN_STATUS_ERROR = -1, /**< Error status. */
  OSP_SCAN_STATUS_INIT,       /**< Init status. */
  OSP_SCAN_STATUS_RUNNING,    /**< Running status. */
  OSP_SCAN_STATUS_STOPPED,    /**< Stopped status. */
  OSP_SCAN_STATUS_FINISHED,   /**< Finished status. */
} osp_scan_status_t;


typedef struct {
  const char *scan_id; ///< UUID of the scan which get the status from.
} osp_get_scan_status_opts_t;

typedef struct {
  int start;    /**< Start interval. */
  int end;      /**< End interval. */
  char *titles; /**< Graph title. */
} osp_get_performance_opts_t;

typedef struct osp_param osp_param_t;

/* OSP Connection handling */

osp_connection_t *
osp_connection_new (const char *, int, const char *, const char *,
                    const char *);

void
osp_connection_close (osp_connection_t *);

/* OSP commands */
int
osp_get_version (osp_connection_t *, char **, char **, char **, char **,
                 char **, char **);

int
osp_get_vts_version (osp_connection_t *, char **);

int
osp_get_vts (osp_connection_t *, entity_t *);

typedef struct {
  char *filter; ///< the filter to apply for a vt sub-selection.
} osp_get_vts_opts_t;

int
osp_get_vts_ext (osp_connection_t *, osp_get_vts_opts_t, entity_t *);

int
osp_start_scan (osp_connection_t *, const char *, const char *, GHashTable *,
                const char *, char **);

typedef struct {
  GSList *targets;              ///< Target hosts to scan.
  GSList *vt_groups;            ///< VT groups to use for the scan.
  GSList *vts;                  ///< Single VTs to use for the scan.
  GHashTable *scanner_params;   ///< Table of scanner parameters.
  int parallel;                 ///< Number of parallel scans.
  const char *scan_id;          ///< UUID to set for scan, null otherwise.
} osp_start_scan_opts_t;

int
osp_start_scan_ext (osp_connection_t *, osp_start_scan_opts_t, char **);

int
osp_get_scan (osp_connection_t *, const char *, char **, int, char **);

int
osp_get_scan_pop (osp_connection_t *,
                  const char *,
                  char **,
                  int,
                  int,
                  char **);

osp_scan_status_t
osp_get_scan_status_ext (osp_connection_t *,
                         osp_get_scan_status_opts_t,
                         char **);

int
osp_delete_scan (osp_connection_t *, const char *);

int
osp_stop_scan (osp_connection_t *, const char *, char **);

int
osp_get_scanner_details (osp_connection_t *, char **, GSList **);


int
osp_get_performance_ext (osp_connection_t *,
                         osp_get_performance_opts_t,
                         char **,
                         char **);

/* OSP scanner parameters handling */

osp_param_t *
osp_param_new (void);

const char *
osp_param_id (const osp_param_t *);

const char *
osp_param_name (const osp_param_t *);

const char *
osp_param_desc (const osp_param_t *);

const char *
osp_param_default (const osp_param_t *);

const char *
osp_param_type_str (const osp_param_t *);

int
osp_param_mandatory (const osp_param_t *);

void
osp_param_free (osp_param_t *);

/* OSP credential handling */

osp_credential_t *
osp_credential_new (const char *, const char *, const char *);

void
osp_credential_free (osp_credential_t *);

const gchar*
osp_credential_get_auth_data (osp_credential_t *, const char*);

void
osp_credential_set_auth_data (osp_credential_t *, const char*, const char*);


/* OSP targets handling */

osp_target_t *
osp_target_new (const char *, const char *, const char *);

void
osp_target_set_finished_hosts (osp_target_t *, const char *);

void
osp_target_free (osp_target_t *);

void
osp_target_add_credential (osp_target_t *, osp_credential_t *);

/* OSP VT group handling */

osp_vt_group_t *
osp_vt_group_new (const char *);

void
osp_vt_group_free (osp_vt_group_t *);

/* OSP single VT handling */

osp_vt_single_t *
osp_vt_single_new (const char *);

void
osp_vt_single_free (osp_vt_single_t *);

void
osp_vt_single_add_value (osp_vt_single_t *, const char*, const char*);

#endif
