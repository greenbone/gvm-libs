/* SPDX-FileCopyrightText: 2010-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Credential pairs and triples.
 */

#ifndef _GVM_BASE_CREDENTIALS_H
#define _GVM_BASE_CREDENTIALS_H

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
  ///< Timezone of user.
  /*@null@ */ double default_severity;
  ///< Default Severity setting of user.
  /*@null@ */ gchar *severity_class;
  ///< Severity Class setting of user.
  /*@null@ */ int dynamic_severity;
  ///< Dynamic Severity setting of user.
  /*@null@ */ gchar *role;
  ///< Role of user.
  /*@null@ */ int excerpt_size;
  ///< Note/Override Excerpt Size setting of user.
} credentials_t;

void
free_credentials (credentials_t *credentials);

void
append_to_credentials_username (credentials_t *credentials, const char *text,
                                gsize length);

void
append_to_credentials_password (credentials_t *credentials, const char *text,
                                gsize length);

#endif /* not _GVM_BASE_CREDENTIALS_H */
