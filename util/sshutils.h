/* Copyright (C) 2015-2022 Greenbone AG
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
 * @brief SSH related API.
 */

#ifndef _GVM_SSHUTILS_H
#define _GVM_SSHUTILS_H

char *
gvm_ssh_pkcs8_decrypt (const char *, const char *);

char *
gvm_ssh_public_from_private (const char *, const char *);

#endif /* not _GVM_SSHUTILS_H */
