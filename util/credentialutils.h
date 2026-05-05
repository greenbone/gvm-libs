/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Functions for handling scan credentials.
 */

#ifndef _GVM_UTIL_CREDENTIALUTILS_H
#define _GVM_UTIL_CREDENTIALUTILS_H

#include <glib.h> /* for GHashTable, GSList */

typedef struct scan_credential scan_credential_t;

scan_credential_t *
scan_credential_new (const char *, const char *, const char *);

void
scan_credential_free (scan_credential_t *);

const gchar *
scan_credential_get_auth_data (scan_credential_t *, const char *);

void
scan_credential_set_auth_data (scan_credential_t *, const char *, const char *);

const gchar *
scan_credential_get_type (scan_credential_t *);

const gchar *
scan_credential_get_service (scan_credential_t *);

const gchar *
scan_credential_get_port (scan_credential_t *);

void
scan_credential_foreach_auth_data (scan_credential_t *,
                                   void (*func) (const char *, const char *,
                                                 void *),
                                   void *);

#endif /* not _GVM_UTIL_CREDENTIALUTILS_H */
