/* Copyright (C) 2020-2021 Greenbone Networks GmbH
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

#include "boreas_error.h"

#include <glib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

/**
 * @brief Transform Boreas error code into human readable error message.
 *
 * @param boreas_error Boreas error code.
 *
 * @return String representation of supplied error code.
 */
const char *
str_boreas_error (boreas_error_t boreas_error)
{
  const gchar *msg;

  msg = NULL;
  switch (boreas_error)
    {
    case BOREAS_OPENING_SOCKET_FAILED:
      msg = "Boreas was not able to open a new socket";
      break;
    case BOREAS_SETTING_SOCKET_OPTION_FAILED:
      msg = "Boreas was not able to set socket option for socket";
      break;
    case BOREAS_NO_VALID_ALIVE_TEST_SPECIFIED:
      msg =
        "No valid alive detection method was specified for Boreas by the user";
      break;
    case BOREAS_CLEANUP_ERROR:
      msg = "Boreas encountered an error during clean up.";
      break;
    case BOREAS_NO_SRC_ADDR_FOUND:
      msg = "Boreas was not able to determine a source address for the given "
            "destination.";
      break;
    case NO_ERROR:
      msg = "No error was encountered by Boreas";
      break;
    default:
      break;
    }
  return msg;
}
