/* SPDX-FileCopyrightText: 2010-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Privilege dropping header file.
 */

#ifndef _GVM_DROP_PRIVILEGES_H
#define _GVM_DROP_PRIVILEGES_H

#include <glib.h>

/**
 * @brief The GQuark for privilege dropping errors.
 */
#define GVM_DROP_PRIVILEGES \
  g_quark_from_static_string ("gvm-drop-privileges-error-quark")

/**
 * @brief Definition of the return code ERROR_ALREADY_SET.
 */
#define GVM_DROP_PRIVILEGES_ERROR_ALREADY_SET -1

/**
 * @brief Definition of the return code OK.
 */
#define GVM_DROP_PRIVILEGES_OK 0

/**
 * @brief Definition of the return code FAIL_NOT_ROOT.
 */
#define GVM_DROP_PRIVILEGES_FAIL_NOT_ROOT 1

/**
 * @brief Definition of the return code FAIL_UNKNOWN_USER.
 */
#define GVM_DROP_PRIVILEGES_FAIL_UNKNOWN_USER 2

/**
 * @brief Definition of the return code FAIL_DROP_GID.
 */
#define GVM_DROP_PRIVILEGES_FAIL_DROP_GID 3

/**
 * @brief Definition of the return code FAIL_DROP_UID.
 */
#define GVM_DROP_PRIVILEGES_FAIL_DROP_UID 4

/**
 * @brief Definition of the return code FAIL_SUPPLEMENTARY.
 */
#define GVM_DROP_PRIVILEGES_FAIL_SUPPLEMENTARY 5

int
drop_privileges (gchar *username, GError **error);

#endif
