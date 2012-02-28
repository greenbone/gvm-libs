/* OpenVAS Libraries
 * $Id$
 * Description: Header for LDAP-Connect Authentication module.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
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

#ifndef ENABLE_LDAP_AUTH
// Handle cases where openldap is not available.
#else

#ifndef LDAP_CONNECT_AUTH_H
#define LDAP_CONNECT_AUTH_H

#include <glib.h>
#include <ldap.h>

int ldap_connect_authenticate (const gchar * username, const gchar * password,
                       /*ldap_auth_info_t */ void *info);

#endif /* not LDAP_CONNECT_AUTH_H */

#endif /* ENABLE_LDAP_AUTH */
