/* openvas-libraries/base
 * $Id$
 * Description: API for OSP communication.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
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

#ifndef _OPENVAS_OSP_H
#define _OPENVAS_OSP_H


typedef struct osp_connection osp_connection_t;

osp_connection_t *
osp_connection_new (const char *, int, const char *, const char *,
                    const char *);

int
osp_get_scanner_version (osp_connection_t *, char **);

char *
osp_start_scan (osp_connection_t *, const char *, void *);

int
osp_get_scan (osp_connection_t *, const char *, char **);

void
osp_connection_close (osp_connection_t *);
#endif
