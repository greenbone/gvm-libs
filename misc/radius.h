/* openvas-libraries/nasl
 * $Id$
 * Description: Headers of an API for Radius authentication.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2015 Greenbone Networks GmbH
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef RADIUS_CONNECT_AUTH_H
#define RADIUS_CONNECT_AUTH_H

int
radius_authenticate (const char *, const char *, const char *, const char *);

#endif /* not RADIUS_CONNECT_AUTH_H */

