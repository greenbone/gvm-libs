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

#ifndef BOREAS_ERROR_H
#define BOREAS_ERROR_H

/**
 * @brief Alive detection error codes.
 */
typedef enum
{
  BOREAS_OPENING_SOCKET_FAILED = -100,
  BOREAS_SETTING_SOCKET_OPTION_FAILED,
  BOREAS_NO_VALID_ALIVE_TEST_SPECIFIED,
  BOREAS_CLEANUP_ERROR,
  BOREAS_NO_SRC_ADDR_FOUND,
  NO_ERROR = 0,
} boreas_error_t;

const char *str_boreas_error (boreas_error_t);

#endif /* not BOREAS_ERROR_H */
