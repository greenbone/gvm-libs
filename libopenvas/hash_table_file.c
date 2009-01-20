/* OpenVAS-Client
 * $Id$
 * Description: Functions to write and read a GHashTable to / from a file.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2008 Intevation GmbH
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
 *
 * In addition, as a special exception, you have
 * permission to link the code of this program with the OpenSSL
 * library (or with modified versions of OpenSSL that use the same
 * license as OpenSSL), and distribute linked combinations including
 * the two. You must obey the GNU General Public License in all
 * respects for all of the code used other than OpenSSL. If you
 * modify this file, you may extend this exception to your version
 * of the file, but you are not obligated to do so. If you do not
 * wish to do so, delete this exception statement from your version.
 */

/**
 * @file
 * Functions to create a GKeyFile from a GHashTable to vice versa.
 * Both are assumed to contain strings only.
 * Groups are ignored for the time being.
 * 
 */

#include "includes.h"

#include "hash_table_file.h"

/**
 * Groupname placeholder. So far, no further order (like groups) has been
 * needed.
 */
#define GROUP_NONE "GHashTableGKeyFile"

/**
 * @brief Adds a key/value pair of strings to a keyfile.
 * 
 * The group for this entry will be GROUP_NONE (define).
 * Of main use within a g_hash_table_foreach.
 * 
 * @param key The key to add.
 * @param value The value to add.
 * @param file The Key/value file (userdata).
 */
static void
add_to_keyfile (char* key_str, char* value_str, GKeyFile* keyfile)
{
  g_key_file_set_string (keyfile, GROUP_NONE, key_str, value_str);
}

/**
 * @brief  Writes key/value pairs from a g_hash_table into a key/value file.
 * 
 * This procedure will only work with string keys and string values.
 * The file format follows freedesktop.org specifications, the group will be
 * GROUP_NONE (define).
 * 
 * @param ghashtable The hashtable to read key/value pairs from.
 * @param filename The filename for the key/value file.
 * 
 * @return TRUE in case of success, FALSE otherwise.
 * 
 * @see hash_table_file_read
 * @see GKeyFile
 */
gboolean
hash_table_file_write (GHashTable* ghashtable, char* filename)
{
  int fd;
  gchar* keyfile_data;
  gsize data_length;
  GKeyFile* file;

  // Initialize the key file
  file = g_key_file_new ();
  g_key_file_set_comment (file, GROUP_NONE, NULL,
                         "Automatically generated file - please to not edit",
                         NULL);
  // Add the entries of the hashtable to the keyfile (in mem)
  g_hash_table_foreach (ghashtable, (GHFunc) add_to_keyfile, file);

  // Open a file to write content to.
  // (with GLIB >= 2.8 we can use file_set_contents)
  fd = open (filename, O_RDWR|O_CREAT|O_TRUNC, 0600);
  if (!fd)
    {
      g_key_file_free (file);
      return FALSE;
    }

  // "Export" data and write it to file.
  keyfile_data = g_key_file_to_data (file, &data_length, NULL);
  int written = write (fd, keyfile_data, data_length);
  
  // Clean up
  close (fd);
  g_free(keyfile_data);
  g_key_file_free(file);
  
  if (written != data_length)
  {
    return FALSE;
  }

  // Assume that went just fine
  return TRUE;
}

/**
 * @brief Reads key/value pairs (strings) from a file back into a GHashtable.
 * 
 * The file has to follow freedesktop.org specifications.
 * 
 * @param filename The filename to read from.
 * @return A GHashTable, mirroring the file or NULL in case of an error.
 * 
 * @see hash_table_file_write
 * @see GKeyFile
 */
GHashTable*
hash_table_file_read (char* filename)
{
  GKeyFile* file = NULL;
  gchar** keys;
  gchar** keys_it;
  gsize length;
  GHashTable* returntable = NULL;
  
  // Load key file into mem
  file = g_key_file_new ();
  g_key_file_load_from_file (file, filename, G_KEY_FILE_NONE, NULL);
  if (file == NULL)
    {
      return NULL;
    }
  
  returntable = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  keys = g_key_file_get_keys (file, GROUP_NONE, &length, NULL);
  keys_it = keys;
  
  // Add each key / value pair from file
  while ( keys_it != NULL && (*keys_it) != NULL)
    {
      char* value = g_key_file_get_value (file, GROUP_NONE, (*keys_it), NULL);
      g_hash_table_insert (returntable, estrdup(*keys_it), value);
      ++keys_it;
    }
  
  if (keys != NULL)
    g_strfreev (keys);

  g_key_file_free(file);
  return returntable;
}
