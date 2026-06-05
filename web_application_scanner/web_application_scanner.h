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
typedef struct web_application_target web_application_target_t;

web_application_target_t *
web_application_target_new (const gchar *, const gchar *, const gchar *);

void
web_application_target_free (web_application_target_t *);

void
web_application_target_add_credential (web_application_target_t *,
                                       scan_credential_t *);

char *
web_application_build_scan_config_json (web_application_target_t *target,
                                        GHashTable *scan_preferences);

#endif /* not _GVM_WEB_APPLICATION_SCANNER_H */
