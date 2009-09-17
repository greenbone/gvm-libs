/* OpenVAS-Client
 * $Id$
 * Description: Convenience functions for GHashTables.
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

#include "hash_table_util.h"

/** @file
 * Convenience functions for GHashTables.
 *
 * @TODO Note that some of the code might get obsolete with future version of
 * GLib.
 *
 * @TODO This module is a candidate for a util library (as it is not specific
 * to OPENVAS).
 */

/**
 * @brief A List and a comparison function.
 *
 * To be used internally as data element for a callback function.
 *
 * @see add_key_to_list, keys_as_string_list
 */
struct list_and_cmpfunc
{
  GSList * list;
  GCompareFunc cmp_func;
} list_and_cmpfunc;

/**
 * @brief As a callback in @ref keys_as_string_list, adds keys (optionally
 * @brief sorted to a list).
 *
 * Keys are assumed to be of type gchar*.
 *
 * @param key           Key of a GHashTable.
 * @param value         Value of a GHashTable (ignored).
 * @param list_and_cmpf Data- element holds list and compare function.
 */
static void
add_key_to_list (gchar* key, gpointer value,
                 struct list_and_cmpfunc* list_and_cmpf)
{
  GSList * list = list_and_cmpf->list;
  if (list_and_cmpf->cmp_func)
    {
      list_and_cmpf->list = g_slist_insert_sorted (list, key,
                                                   list_and_cmpf->cmp_func);
    }
  else
    {
      list_and_cmpf->list = g_slist_append (list, key);
    }
}

/**
 * @brief Returns a list of keys (assumed to be strings) of a given GHashTable
 * @brief that is optionally sorted.
 *
 * @TODO Note that with GLib 2.14 this function is obsolete, as Glib 2.14
 *       defines g_hash_table_get_keys ().
 *
 * @param hash_table The GHashTable whose keys to return.
 * @param cmp_func   (can be NULL) String comparison function if the returned
 *                   list shall be sorted.
 *
 * @return A GSList containing pointers to the keys of the given GHashTable.
 */
GSList *
keys_as_string_list (GHashTable* hash_table, GCompareFunc cmp_func)
{
  struct list_and_cmpfunc list_and_cmpf;
  list_and_cmpf.list     = NULL;
  list_and_cmpf.cmp_func = NULL;

  g_hash_table_foreach (hash_table, (GHFunc) add_key_to_list, &list_and_cmpf);

  return list_and_cmpf.list;
}
