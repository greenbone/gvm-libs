/* Copyright (C) 2017-2021 Greenbone Networks GmbH
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
 * @brief Implementation of sentry methods.
 *
 * This file contains all methods needed for sentry. To enable sentry and log
 * log in the sentry server, methods in this file are called.
 *
 */

#ifndef _GVM_SENTRY_H
#define _GVM_SENTRY_H

#ifdef HAVE_SENTRY
#include <sentry.h>
#endif /* HAVE_SENTRY*/

void
gvm_sentry_init (const char *, const char *);

void
gvm_sentry_log (const char *);

void
gvm_close_sentry (void);

int
gvm_has_sentry_support (void);

#endif /* not _GVM_SENTRY_H */
