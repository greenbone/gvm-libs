/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Openvas Daemon communication.
 */

#ifndef _GVM_OPENVASD_H
#define _GVM_OPENVASD_H

#include "../base/nvti.h"
#include "../http_scanner/http_scanner.h"
#include "../util/jsonpull.h"

#include <glib.h>
#include <stdio.h>
#include <time.h>

typedef struct
{
  int start;           /**< Start interval. */
  int end;             /**< End interval. */
  const gchar *titles; /**< Graph title. */
} openvasd_get_performance_opts_t;

// Requests
http_scanner_resp_t openvasd_get_vts (http_scanner_connector_t);

http_scanner_resp_t openvasd_get_performance (http_scanner_connector_t,
                                              openvasd_get_performance_opts_t);
int
openvasd_parsed_performance (http_scanner_connector_t,
                             openvasd_get_performance_opts_t, gchar **,
                             gchar **err);

/* Target builder */
typedef struct openvasd_target openvasd_target_t;

typedef struct openvasd_vt_single openvasd_vt_single_t;

typedef struct openvasd_credential openvasd_credential_t;

openvasd_target_t *
openvasd_target_new (const gchar *, const gchar *, const gchar *, const gchar *,
                     int, int);

void
openvasd_target_set_finished_hosts (openvasd_target_t *, const gchar *);

void
openvasd_target_add_alive_test_methods (openvasd_target_t *, gboolean, gboolean,
                                        gboolean, gboolean, gboolean);

void
openvasd_target_free (openvasd_target_t *);

openvasd_credential_t *
openvasd_credential_new (const gchar *, const gchar *, const gchar *);

void
openvasd_credential_set_auth_data (openvasd_credential_t *, const gchar *,
                                   const gchar *);
void
openvasd_credential_free (openvasd_credential_t *);

void
openvasd_target_add_credential (openvasd_target_t *, openvasd_credential_t *);

openvasd_vt_single_t *
openvasd_vt_single_new (const gchar *);

void
openvasd_vt_single_free (openvasd_vt_single_t *);

void
openvasd_vt_single_add_value (openvasd_vt_single_t *, const gchar *,
                              const gchar *);

char *
openvasd_build_scan_config_json (openvasd_target_t *, GHashTable *, GSList *);

/* VT stream */
http_scanner_resp_t openvasd_get_vt_stream_init (http_scanner_connector_t);

int openvasd_get_vt_stream (http_scanner_connector_t);

#endif
