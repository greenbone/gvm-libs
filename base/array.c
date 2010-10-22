/* openvas-libraries/base
 * $Id$
 * Description: Array utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
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
 * @file array.c
 * @brief Array utilities.
 */

#include "array.h"

/**
 * @brief Make a global array.
 *
 * @return New array.
 */
GPtrArray *
make_array ()
{
  return g_ptr_array_new ();
}

/**
 * @brief Reset an array.
 *
 * @param[in]  array  Pointer to array.
 */
void
array_reset (array_t ** array)
{
  array_free (*array);
  *array = make_array ();
}

/**
 * @brief Free global array value.
 *
 * Also g_free any elements.
 *
 * @param[in]  array  Pointer to array.
 */
void
array_free (GPtrArray * array)
{
  if (array)
    {
      guint index = array->len;
      while (index--)
        g_free (g_ptr_array_index (array, index));
      g_ptr_array_free (array, TRUE);
    }
}

/**
 * @brief Push a generic pointer onto an array.
 *
 * @param[in]  array    Array.
 * @param[in]  pointer  Pointer.
 */
void
array_add (array_t * array, gpointer pointer)
{
  if (array)
    g_ptr_array_add (array, pointer);
}

/**
 * @brief Terminate an array.
 */
void
array_terminate (array_t * array)
{
  if (array)
    g_ptr_array_add (array, NULL);
}
