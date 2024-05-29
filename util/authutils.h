/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Authentication mechanism(s).
 */

#ifndef _GVM_AUTHUTILS_H
#define _GVM_AUTHUTILS_H

#include <glib.h>

/**
 * @brief Numerical representation of the supported authentication methods.
 *        Beware to have it in sync with \p authentication_methods in
 *        \ref authutils.c.
 */
enum authentication_method
{
  AUTHENTICATION_METHOD_FILE = 0,
  AUTHENTICATION_METHOD_LDAP_CONNECT,
  AUTHENTICATION_METHOD_RADIUS_CONNECT,
  AUTHENTICATION_METHOD_LAST
};

/** @brief Type for the numerical representation of the supported
 *         authentication methods. */
typedef enum authentication_method auth_method_t;

const gchar *auth_method_name (auth_method_t);

int
auth_method_name_valid (const gchar *);

int
gvm_auth_init (void);

int
gvm_authenticate_classic (const gchar *, const gchar *, const gchar *);

gchar *
get_md5_hash_from_string (const gchar *);

gchar *
get_password_hashes (const gchar *);

gchar *
digest_hex (int, const guchar *);

int
gvm_auth_ldap_enabled (void);

int
gvm_auth_radius_enabled (void);

#endif /* not _GVM_AUTHUTILS_H */
