/* Copyright (C) 2013-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
 * @file
 * @brief API related to data compression (gzip format.)
 */

#ifndef _GVM_COMPRESSUTILS_H
#define _GVM_COMPRESSUTILS_H

void *
gvm_compress (const void *, unsigned long, unsigned long *);

void *
gvm_compress_gzipheader (const void *, unsigned long, unsigned long *);

void *
gvm_uncompress (const void *, unsigned long, unsigned long *);

#endif /* not _GVM_COMPRESSUTILS_H */
