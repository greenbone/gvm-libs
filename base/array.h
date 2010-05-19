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

#ifndef _OPENVAS_ARRAY_H
#define _OPENVAS_ARRAY_H

#include <glib.h>

typedef GPtrArray array_t;

GPtrArray *make_array ();

void array_reset (array_t ** array);

void array_free (GPtrArray * array);

void array_add (array_t * array, gpointer pointer);

void array_terminate (array_t * array);

#endif /* not _OPENVAS_ARRAY_H */
