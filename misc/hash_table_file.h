/* OpenVAS Libraries
 * $Id$
 * Description: Functions to write and read a g_hash_table to / from a file.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
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

/**
 * @file
 * Protos for module hash_table_file.c.
 */

#ifndef _OPENVAS_CLIENT_HASH_TABLE_FILE_H
#define _OPENVAS_CLIENT_HASH_TABLE_FILE_H

#include <glib.h>

GHashTable *hash_table_file_read_text (const char *text, gsize length);

#endif
