/* openvas-libraries/base
 * $Id$
 * Description: API (structs and protos) for configuration file management
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@intevation.de>
 * Michael Wiegand <michael.wiegand@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
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
 * @file settings.h
 * @brief Protos and data structures for configuration file management
 *
 * This file contains the protos for \ref settings.c
 */

#ifndef _OPENVAS_LIBRARIES_BASE_SETTINGS_H
#define _OPENVAS_LIBRARIES_BASE_SETTINGS_H

#include <glib.h>

typedef struct
{
  gchar *file_name;
  gchar *group_name;
  GKeyFile *key_file;
} settings_t;

void settings_cleanup (settings_t *);

typedef struct
{
  gchar **keys;
  settings_t settings;
  gchar **current_key;
  gchar **last_key;
} settings_iterator_t;

int init_settings_iterator_from_file (settings_iterator_t *, const gchar *,
                                      const gchar *);
void cleanup_settings_iterator (settings_iterator_t *);
int settings_iterator_next (settings_iterator_t *);
const gchar *settings_iterator_name (settings_iterator_t *);
const gchar *settings_iterator_value (settings_iterator_t *);

#endif /* not _OPENVAS_LIBRARIES_BASE_SETTINGS_H */
