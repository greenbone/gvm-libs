/* gvm-libs/base
 * $Id$
 * Description: File utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Michael Wiegand <michael.wiegand@greenbone.net
 * Felix Wolfsteller <felix.wolfsteller@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009, 2010, 2016 Greenbone Networks GmbH
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
 * @file fileutils.h
 * @brief Protos for file utility functions.
 *
 * This file contains the protos for \ref fileutil.c
 */

#ifndef _GVM_FILEUTILS_H
#define _GVM_FILEUTILS_H

#include <glib.h>
#include <gio/gio.h>

int gvm_file_check_is_dir (const char *name);

int gvm_file_remove_recurse (const gchar * pathname);

gboolean gvm_file_copy (const gchar *, const gchar *);

gboolean gvm_file_move (const gchar *, const gchar *);

char *gvm_file_as_base64 (const char *);

gchar *gvm_export_file_name (const char *, const char *, const char *,
                             const char *, const char *, const char *,
                             const char *, const char *);

#endif /* not _GVM_FILEUTILS_H */
