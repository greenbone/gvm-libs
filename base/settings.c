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
 * @brief Initialise a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 * @param[in]  filename  Complete name of the configuration file.
 * @param[in]  group     Name of the group in the file.
 *
 * @return 0 success, -1 error.
 */
int
init_settings_iterator (settings_iterator_t *settings, const char *filename,
                        const char *group)
{
  GError* error = NULL;
  gsize keys_length;

  if (filename == NULL || group == NULL)
    return -1;

  settings->key_file = g_key_file_new ();

  if (!g_key_file_load_from_file (settings->key_file, filename, G_KEY_FILE_NONE,
                                  &error))
    {
      g_warning ("Failed to load configuration from %s: %s",
                 filename,
                 error->message);
      g_error_free (error);
      g_key_file_free (settings->key_file);
      return -1;
    }

  settings->keys = g_key_file_get_keys (settings->key_file, group, &keys_length,
                                        &error);

  if (settings->keys == NULL)
    {
      if (error)
        {
          g_warning ("Failed to retrieve keys of group %s from %s: %s", group,
                     filename, error->message);
          g_error_free (error);
        }
      g_key_file_free (settings->key_file);
      return -1;
    }

  settings->current_key = settings->keys - 1;
  settings->last_key = settings->keys + keys_length - 1;
  settings->group_name = g_strdup (group);

  return 0;
}

/**
 * @brief Cleanup a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 */
void
cleanup_settings_iterator (settings_iterator_t *settings)
{
  g_free (settings->group_name);
  g_strfreev (settings->keys);
  g_key_file_free (settings->key_file);
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]  iterator  Settings iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
settings_iterator_next (settings_iterator_t *settings)
{
  if (settings->current_key == settings->last_key)
    return FALSE;
  settings->current_key++;
  return TRUE;
}

/**
 * @brief Get the name from a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 *
 * @return Name of current key.
 */
const gchar *
settings_iterator_name (settings_iterator_t *settings)
{
  return *settings->current_key;
}

/**
 * @brief Get the value from a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 *
 * @return Value of current key.
 */
const gchar *
settings_iterator_value (settings_iterator_t *settings)
{
  return g_key_file_get_value (settings->key_file,
                               settings->group_name,
                               *settings->current_key,
                               NULL);
}
