/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Protos for file utility functions.
 *
 * This file contains the protos for \ref fileutils.c
 */

#ifndef _GVM_FILEUTILS_H
#define _GVM_FILEUTILS_H

#include <glib.h>

int
gvm_file_exists (const char *name);

int
gvm_file_is_executable (const char *name);

int
gvm_file_is_readable (const char *name);

int
gvm_file_check_is_dir (const char *name);

int
gvm_file_remove_recurse (const gchar *pathname);

gboolean
gvm_file_copy (const gchar *, const gchar *);

gboolean
gvm_file_move (const gchar *, const gchar *);

char *
gvm_file_as_base64 (const char *);

gchar *
gvm_export_file_name (const char *, const char *, const char *, const char *,
                      const char *, const char *, const char *, const char *);

#endif /* not _GVM_UTIL_FILEUTILS_H */
