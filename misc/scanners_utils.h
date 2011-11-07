/* OpenVAS Libraries
 * Copyright (C) 1998 Renaud Deraison
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
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * scanners_utils -- scanner-plugins-specific stuff
 */

#ifndef _OPENVAS_SCANNERS_UTILS_H
#define _OPENVAS_SCANNERS_UTILS_H

int comm_send_status (struct arglist *, char *, char *, int, int);
unsigned short *getpts (char *, int *);

#endif
