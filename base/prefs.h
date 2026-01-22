/* SPDX-FileCopyrightText: 2014-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Protos and data structures for NVT Information data sets.
 *
 * This file contains the protos for \ref prefs.c
 */

#ifndef _GVM_BASE_PREFS_H
#define _GVM_BASE_PREFS_H

#include <glib.h> /* for gchar */

void
prefs_config (const char *);
const gchar *
prefs_get (const gchar *key);
int
prefs_get_bool (const gchar *key);
void
prefs_set (const gchar *, const gchar *);
void
prefs_dump (void);
int
prefs_nvt_timeout (const char *);

GHashTable *
preferences_get (void);

#endif /* not _GVM_BASE_PREFS_H */
