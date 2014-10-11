/* OpenVAS
 * $Id$
 * Description: Memory management methods.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h> /* for strlen */
#include <glib.h>   /* for g_malloc0 */

/**
 * This method is a wrapper for g_malloc0 unti all calls
 * replaced by direct calls of g_malloc0.
 */
void *
emalloc (size_t size)
{
  /* Previously this function always added 1 byte. Removing this
     extra byte significantly improves the memory footprint
     but also some scan parts do not work like before anymore.
     So, all single uses of emalloc should be carefully analysed
     before using g_malloc0 directly. */

  return g_malloc0 (size + 1);
}

void
efree (void *ptr)
{
  char **p = ptr;
  if (p && *p)
    {
      g_free (*p);
      *p = NULL;
    }
}

void *
erealloc (void *ptr, size_t size)
{
  return  g_realloc (ptr, size);
}

