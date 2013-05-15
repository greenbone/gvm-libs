/* OpenVAS Libraries
 * $Id$
 * Description: Header for authentication mechanism(s).
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef _OPENVAS_AUTH_H
#define _OPENVAS_AUTH_H

#include <glib.h>

#include "../base/array.h"

/**
 * @brief Numerical representation of the supported authentication methods.
 * @brief Beware to have it in sync with \ref authentication_methods.
 */
enum authentication_method
{
  AUTHENTICATION_METHOD_FILE = 0,
  AUTHENTICATION_METHOD_ADS,
  AUTHENTICATION_METHOD_LDAP,
  AUTHENTICATION_METHOD_LDAP_CONNECT,
  AUTHENTICATION_METHOD_LAST
};

/** @brief Type for the numerical representation of the supported
 *  @brief authentication methods. */
typedef enum authentication_method auth_method_t;

const gchar *auth_method_name (auth_method_t);

void openvas_auth_init ();

void openvas_auth_init_funcs (gchar * (*) (const gchar *),
                              int (*) (const gchar *, const gchar *,
                                       const gchar *),
                              int (*) (const gchar *, auth_method_t),
                              int (*) (const gchar *, const gchar *,
                                       const gchar *, int),
                              gchar * (*) (const gchar *, auth_method_t));

void openvas_auth_tear_down ();

int openvas_auth_write_config (GKeyFile * keyfile);

gchar *get_password_hashes (int, const gchar *);

gchar *digest_hex (int, const guchar *);

int openvas_authenticate_method (const gchar *, const gchar *, auth_method_t *);

int openvas_authenticate (const gchar *, const gchar *);

int openvas_authenticate_uuid (const gchar *, const gchar *, gchar ** uuid);

int openvas_user_exists (const char *);

gchar *openvas_user_uuid (const char *name);

int openvas_is_user_admin (const gchar *);

int openvas_is_user_observer (const gchar *);

int openvas_set_user_role (const gchar *, const gchar *,
                           const gchar * user_dir_name);

GString *openvas_auth_make_user_rules (const gchar *, int);
GSList *
openvas_auth_user_methods (const gchar * user_name);

int
openvas_auth_user_set_allowed_methods (const gchar * username,
                                  const array_t * allowed_methods);

#endif /* not _OPENVAS_AUTH_H */
