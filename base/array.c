/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Array utilities.
 */

#include "array.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/**
 * @brief Make a global array.
 *
 * @return New array.
 */
GPtrArray *
make_array (void)
{
  return g_ptr_array_new ();
}

/**
 * @brief Reset an array.
 *
 * @param[in]  array  Pointer to array.
 */
void
array_reset (array_t **array)
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
array_free (GPtrArray *array)
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
array_add (array_t *array, gpointer pointer)
{
  if (array)
    g_ptr_array_add (array, pointer);
}

/**
 * @brief Terminate an array.
 *
 * @param[in]  array    Array.
 */
void
array_terminate (array_t *array)
{
  if (array)
    g_ptr_array_add (array, NULL);
}
