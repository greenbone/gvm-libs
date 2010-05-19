/* OpenVAS Libraries
 * $Id$
 * Description: UUID creation.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 * Felix Wolfsteller <felix.wolfsteller@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "openvas_uuid.h"

#include <glib.h>
#include <stdlib.h>
#include <uuid/uuid.h>


/**
 * @brief Make a new universal identifier.
 *
 * @return A newly allocated string holding the identifier, which the
 *         caller must free, or NULL on failure.
 */
char *
openvas_uuid_make ()
{
  char *id;
  uuid_t uuid;

  /* Generate an UUID. */
  uuid_generate (uuid);
  if (uuid_is_null (uuid) == 1)
    {
      g_warning ("%s: failed to generate UUID", __FUNCTION__);
      return NULL;
    }

  /* Allocate mem for string to hold UUID. */
  id = malloc (sizeof (char) * 37);
  if (id == NULL)
    {
      g_warning ("%s: Cannot export UUID to text: out of memory", __FUNCTION__);
      return NULL;
    }

  /* Export the UUID to text. */
  uuid_unparse (uuid, id);

  return id;
}
