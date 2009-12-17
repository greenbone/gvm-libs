/* openvas-libraries/base
 * $Id$
 * Description: Implementation of API to handle configuration file management
 *
 * Authors:
 * Michael Wiegand <michael.wiegand@intevation.de>
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
 * @file settings.c
 * @brief Implementation of API to handle configuration file management
 *
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include "settings.h"

/**
 * @brief Returns a HashTable of setting retrieved from a given group of
 * an configuration file.
 *
 * @param filename The complete name of the configuration file.
 * @param group The name of the group.
 *
 * @return A pointer to a GHashTable containing key/value pairs of all
 * settings found in the group or NULL if the file contents could not be
 * accessed. The HashTable should be freed with g_hash_table_destroy() when no
 * longer needed.
 */
GHashTable *
get_all_settings (const gchar * filename, const gchar * group)
{
  g_assert (filename);
  g_assert (group);

  GKeyFile* settingskeyfile = g_key_file_new ();
  GError* error = NULL;
  gchar** keys = NULL;
  GHashTable* settings = NULL;
  int i;

  if (! g_key_file_load_from_file (settingskeyfile, filename,
                                   G_KEY_FILE_NONE, &error))
    {
      g_warning ("Failed to load configuration from %s: %s", filename,
                 error->message);
      g_key_file_free (settingskeyfile);
      g_error_free (error);
      return NULL;
    }

  keys =  g_key_file_get_keys (settingskeyfile, group, NULL, &error);

  if (keys == NULL)
    {
      if (error)
        {
          g_warning ("Failed to retrieve keys of group %s from %s: %s", group,
                     filename, error->message);
          g_error_free (error);
        }
      g_key_file_free (settingskeyfile);
      return NULL;
    }

  settings = g_hash_table_new (g_str_hash, g_str_equal);

  for (i = 0; i < g_strv_length (keys); i++)
    {
      gchar* value = g_key_file_get_value (settingskeyfile, group,
                                           keys[i], &error);
      g_hash_table_insert (settings, g_strdup (keys[i]), g_strdup (value));
      g_free (value);
    }

  g_strfreev (keys);
  g_key_file_free (settingskeyfile);

  return settings;
}

