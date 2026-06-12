/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Web Application Scanner communication.
 */

#ifndef _GVM_WEB_APPLICATION_SCANNER_H
#define _GVM_WEB_APPLICATION_SCANNER_H

#include "../util/credentialutils.h"

#include <glib.h>

/* Target builder */
typedef struct web_scanner_target web_scanner_target_t;

typedef struct web_scanner_vt_single web_scanner_vt_single_t;

web_scanner_target_t *
web_scanner_target_new (const gchar *, const gchar *, const gchar *);

void
web_scanner_target_free (web_scanner_target_t *);

void
web_scanner_target_add_credential (web_scanner_target_t *, scan_credential_t *);

char *
web_scanner_build_scan_config_json (web_scanner_target_t *target,
                                    GHashTable *scan_preferences, GSList *vts);

#endif /* not _GVM_WEB_APPLICATION_SCANNER_H */
