/* OpenVAS Libraries
 * $Id$
 * Description: Functions to write and read a GHashTable to / from a file.
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
 * Functions to create a GKeyFile from a GHashTable and vice versa.
 * Both are assumed to contain strings only.
 * Key-value pairs are 'flat', the structuring group- elements of an GKeyFile
 * are not used. Instead, all pairs are written added to the group
 * "GHashTableGKeyFile" (defined in GROUP_NONE).
 */

/* for open() */
#include <fcntl.h>

/* for close() */
#include <unistd.h>

/* for estrdup() */
#include "system.h"

#include "hash_table_file.h"

/**
 * @brief Groupname placeholder. So far, no further order (like groups) is
 *        supported.
 */
#define GROUP_NONE "GHashTableGKeyFile"

/**
 * @brief Reads key/value pairs (strings) from a GKeyFile into a GHashtable.
 *
 * Will free the GKeyFile.
 *
 * @param gkeyfile GKeyFile to use, will be freed.
 *
 * @return A GHashTable, mirroring the file or NULL in case of an error.
 */
static GHashTable *
hash_table_from_gkeyfile (GKeyFile * gkeyfile)
{
  gchar **keys;
  gchar **keys_it;
  gsize length;
  GHashTable *returntable = NULL;

  if (!gkeyfile)
    return NULL;

  returntable = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  keys = g_key_file_get_keys (gkeyfile, GROUP_NONE, &length, NULL);
  keys_it = keys;

  // Add each key / value pair from file
  while (keys_it != NULL && (*keys_it) != NULL)
    {
      char *value =
        g_key_file_get_value (gkeyfile, GROUP_NONE, (*keys_it), NULL);
      g_hash_table_insert (returntable, estrdup (*keys_it), value);
      ++keys_it;
    }

  if (keys != NULL)
    g_strfreev (keys);

  g_key_file_free (gkeyfile);

  return returntable;
}

/**
 * @brief Reads key/value pairs (strings) from a text into a GHashtable.
 *
 * The text has to follow freedesktop.org specifications (e.g. be the text
 * of a ini- file).
 *
 * @param text   The text to use.
 * @param length Lenght of \ref text.
 *
 * @return A GHashTable, mirroring the text or NULL in case of an error.
 *
 * @see GKeyFile
 */
GHashTable *
hash_table_file_read_text (const char *text, gsize length)
{
  GKeyFile *file = NULL;

  // Load key file from mem
  file = g_key_file_new ();
  g_key_file_load_from_data (file, text, length, G_KEY_FILE_NONE, NULL);

  return hash_table_from_gkeyfile (file);
}
