/* openvas-libraries/misc
 * $Id$
 * Description:  API (protos) for globally stored preferences
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
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

/**
 * @file prefs.h
 * @brief Protos and data structures for NVT Information data sets.
 *
 * This file contains the protos for \ref nvti.c
 */

#ifndef _OPENVAS_PREFS_H
#define _OPENVAS_PREFS_H

#include <glib.h> /* for gchar */

void prefs_config (const char *);
const gchar * prefs_get (const gchar * key);
int prefs_get_bool (const gchar * key);
void prefs_set (const gchar *, const gchar *);
void prefs_dump (void);
int prefs_nvt_timeout (const char *);

struct arglist * preferences_get (void);

#endif /* not _OPENVAS_PREFS_H */
