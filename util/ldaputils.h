/* SPDX-FileCopyrightText: 2012-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Header for LDAP-Connect Authentication module.
 */

#ifndef _GVM_LDAPUTILS_H
#define _GVM_LDAPUTILS_H

#include <glib.h>

/** @brief Authentication schema and address type. */
typedef struct ldap_auth_info *ldap_auth_info_t;

/**
 * @brief Schema (dn) and info to use for a basic ldap authentication.
 *
 * Use like an opaque struct, create with ldap_auth_schema_new, do not modify,
 * free with ldap_auth_schema_free.
 */
struct ldap_auth_info
{
  gchar *ldap_host;         ///< Address of the ldap server, might include port.
  gchar *auth_dn;           ///< DN to authenticate with.
  gboolean allow_plaintext; ///< !Whether or not StartTLS or LDAPS is required.
  gboolean ldaps_only;      ///< Whether to try LDAPS before StartTLS.
};

int
ldap_enable_debug (void);

int
ldap_connect_authenticate (const gchar *, const gchar *,
                           /* ldap_auth_info_t */ void *, const gchar *);

void ldap_auth_info_free (ldap_auth_info_t);

ldap_auth_info_t
ldap_auth_info_new (const gchar *, const gchar *, gboolean);

ldap_auth_info_t
ldap_auth_info_new_2 (const gchar *, const gchar *, gboolean, gboolean);

#ifdef ENABLE_LDAP_AUTH

#include <ldap.h>

gchar *
ldap_auth_info_auth_dn (const ldap_auth_info_t, const gchar *);

LDAP *
ldap_auth_bind (const gchar *, const gchar *, const gchar *, gboolean,
                const gchar *);

LDAP *
ldap_auth_bind_2 (const gchar *, const gchar *, const gchar *, gboolean,
                  const gchar *, gboolean);

gboolean
ldap_auth_dn_is_good (const gchar *);

#endif /* ENABLE_LDAP_AUTH */

#endif /* not _GVM_LDAPUTILS_H */
