/* openvas-libraries/base
 * $Id$
 * Description: String utilities.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
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

#ifndef _OPENVAS_LIBRARIES_STRING_H
#define _OPENVAS_LIBRARIES_STRING_H

#include <glib.h>

typedef gchar *string;

void openvas_append_string (string *, const gchar *);
void openvas_append_text (string *, const gchar *, gsize);
void openvas_free_string_var (string *);

char *openvas_strip_space (char *, char *);

gchar* openvas_string_flatten_string_list (GSList* string_list,
                                           const gchar* separator);

void openvas_string_list_free (GSList* string_list);

#endif /* not _OPENVAS_LIBRARIES_STRING_H */
