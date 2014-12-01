/* openvas-libraries/base
 * $Id$
 * Description: Credential pairs and triples.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Michael Wiegand <michael.wiegand@intevation.de>
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
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

#ifndef _OPENVAS_LIBRARIES_BASE_CREDENTIALS_H
#define _OPENVAS_LIBRARIES_BASE_CREDENTIALS_H

#include "credentials.h"

#include <glib.h>

/**
 * @brief A username password pair.
 */
typedef struct
{
  /*@null@ */ gchar *username;
  ///< Login name of user.
  /*@null@ */ gchar *password;
  ///< Password of user.
  /*@null@ */ gchar *uuid;
  ///< UUID of user.
  /*@null@ */ gchar *timezone;
  ///< Timezone of user.  Set in OpenVAS Manager.
  /*@null@ */ gchar *severity_class;
  ///< Severity Class setting of user.  Set in OpenVAS Manager.
  /*@null@ */ int dynamic_severity;
  ///< Dynamic Severity setting of user.  Set in OpenVAS Manager.
  /*@null@ */ gchar *role;
  ///< Role of user.
} credentials_t;

void free_credentials (credentials_t * credentials);

void append_to_credentials_username (credentials_t * credentials,
                                     const char *text, gsize length);

void append_to_credentials_password (credentials_t * credentials,
                                     const char *text, gsize length);

#endif /* _OPENVAS_LIBRARIES_BASE_CREDENTIALS_H */
