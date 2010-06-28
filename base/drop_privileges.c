/* openvas-libraries/base
 * $Id$
 * Description: Privilege dropping.
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

/**
 * @file drop_privileges.c
 *
 * Basic support to drop privileges.
 */


/** @todo Eliminate both portability and security issues. */


#include "drop_privileges.h"

#include <pwd.h>
#include <unistd.h>


/**
 * @brief Sets an error and return \param errorcode.
 *
 * @param error     Error to set.
 * @param errorcode Errorcode (possible values defined in drop_privileges.h),
 *                  will be returned.
 * @param message   Message to attach to the error.
 *
 * @return \param errorcode.
 */
static gint
drop_privileges_error (GError ** error, gint errorcode, const gchar * message)
{
  g_set_error (error, OPENVAS_DROP_PRIVILEGES, errorcode, "%s", message);
  return errorcode;
}


/**
 * @brief Naive attempt to drop privileges.
 *
 * We try to drop our (root) privileges and setuid to \param username to
 * minimize the risk of privilege escalation.
 * The current implementation is somewhat linux-specific and may not work on
 * other platforms.
 *
 * @param[in]  username The user to become. Its safe to pass "NULL", in which
 *                      case it will default to "nobody".
 * @param[out] error    Return location for errors or NULL if not interested
 *                      in errors.
 *
 * @return OPENVAS_DROP_PRIVILEGES_OK in case of success. Sets \param error
 *         otherwise and returns the error code.
 */
int
drop_privileges (gchar * username, GError ** error)
{
  struct passwd *user_pw = NULL;

  g_return_val_if_fail (*error == NULL,
                        OPENVAS_DROP_PRIVILEGES_ERROR_ALREADY_SET);

  if (username == NULL)
    username = "nobody";

  if (getuid () == 0)
    {
      if ((user_pw = getpwnam (username)))
        {
          if (setgid (user_pw->pw_gid) != 0)
            return drop_privileges_error (error,
                                          OPENVAS_DROP_PRIVILEGES_FAIL_DROP_GID,
                                          "Failed to drop group privileges!\n");
          if (setuid (user_pw->pw_uid) != 0)
            return drop_privileges_error (error,
                                          OPENVAS_DROP_PRIVILEGES_FAIL_DROP_UID,
                                          "Failed to drop user privileges!\n");
        }
      else
        {
          g_set_error (error, OPENVAS_DROP_PRIVILEGES,
                       OPENVAS_DROP_PRIVILEGES_FAIL_UNKNOWN_USER,
                       "Failed to get gid and uid for user %s.", username);
          return OPENVAS_DROP_PRIVILEGES_FAIL_UNKNOWN_USER;
        }
      return OPENVAS_DROP_PRIVILEGES_OK;
    }
  else
    {
      return drop_privileges_error (error,
                                    OPENVAS_DROP_PRIVILEGES_FAIL_NOT_ROOT,
                                    "Only root can drop its privileges.");
    }
}
