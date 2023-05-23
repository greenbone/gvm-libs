/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief String utilities.
 */

#ifndef _GVM_STRINGS_H
#define _GVM_STRINGS_H

#include <glib.h>

void
gvm_append_string (gchar **, const gchar *);
void
gvm_append_text (gchar **, const gchar *, gsize);
void
gvm_free_string_var (gchar **);

char *
gvm_strip_space (char *, char *);

#endif /* not _GVM_STRINGS_H */
