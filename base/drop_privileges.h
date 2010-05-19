/* openvas-libraries/base
 * $Id$
 * Description: Privilege dropping header file.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 * based on work by Michael Wiegand <michael.wiegand@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
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

#ifndef _OPENVAS_LIBRARIES_BASE_DROP_PRIVILEGES_H
#define _OPENVAS_LIBRARIES_BASE_DROP_PRIVILEGES_H

#include <glib.h>

/**
 * @brief The GQuark for privilege dropping errors.
 */
#define OPENVAS_DROP_PRIVILEGES g_quark_from_static_string ("openvas-drop-privileges-error-quark")

/* Definitions of the return codes. */
#define OPENVAS_DROP_PRIVILEGES_ERROR_ALREADY_SET -1

#define OPENVAS_DROP_PRIVILEGES_OK 0
#define OPENVAS_DROP_PRIVILEGES_FAIL_NOT_ROOT 1
#define OPENVAS_DROP_PRIVILEGES_FAIL_UNKNOWN_USER 2
#define OPENVAS_DROP_PRIVILEGES_FAIL_DROP_GID 3
#define OPENVAS_DROP_PRIVILEGES_FAIL_DROP_UID 4

int drop_privileges (gchar * username, GError ** error);

#endif
