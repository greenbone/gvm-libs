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

#include "credentials.h"

#include "openvas_string.h"

/**
 * @brief Free credentials.
 *
 * Free the members of a credentials pair.
 *
 * @param[in]  credentials  Pointer to the credentials.
 */
void
free_credentials (credentials_t * credentials)
{
  g_free (credentials->username);
  credentials->username = NULL;

  g_free (credentials->password);
  credentials->password = NULL;

  /** @todo Check whether uuid has to be freed, too. */

  g_free (credentials->timezone);
  credentials->timezone = NULL;

  g_free (credentials->role);
  credentials->role = NULL;

  g_free (credentials->severity_class);
  credentials->severity_class = NULL;

  credentials->dynamic_severity = 0;
}

/**
 * @brief Append text to the username of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void
append_to_credentials_username (credentials_t * credentials, const char *text,
                                gsize length)
{
  openvas_append_text (&credentials->username, text, length);
}

/**
 * @brief Append text to the password of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void
append_to_credentials_password (credentials_t * credentials, const char *text,
                                gsize length)
{
  openvas_append_text (&credentials->password, text, length);
}
