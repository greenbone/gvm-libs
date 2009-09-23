/* OpenVAS-Client
 * $Id$
 * Description: SSH Key management.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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

#ifndef _OPENVAS_AUTH_H
#define _OPENVAS_AUTH_H

#include <glib.h>

gchar *
get_password_hashes (int, const gchar *);

gchar *
digest_hex (int, const guchar *);

int
openvas_authenticate (const gchar *, const gchar *);

int
openvas_is_user_admin (const gchar *);

int
openvas_set_user_role (const gchar *, const gchar *);

#endif /* not _OPENVAS_AUTH_H */
