/* openvas-libraries/base
 * $Id$
 * Description: API related to data compression (gzip format.)
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
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

#ifndef _OPENVAS_COMPRESS_H
#define _OPENVAS_COMPRESS_H

#include <string.h>
#include <stdlib.h>

void *
openvas_compress (const void *, unsigned long, unsigned long *);

void *
openvas_uncompress (const void *, unsigned long, unsigned long *);

#endif /* not _OPENVAS_COMPRESS_H */
