/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
