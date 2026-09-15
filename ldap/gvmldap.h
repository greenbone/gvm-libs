/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file gvmldap.h
 * @brief LDAP utility functions built on OpenLDAP.
 *
 */

#ifndef _GVM_LDAP_GVMLDAP_H
#define _GVM_LDAP_GVMLDAP_H

#include <ldap.h>
#include <glib.h>

#define GVM_LDAP_DEFAULT_PAGE_SIZE 100

/**
 * @brief LDAP TLS mode enumeration.
 */
typedef enum
{
  GVM_LDAP_TLS_LDAPS,
  GVM_LDAP_TLS_STARTTLS,
  GVM_LDAP_TLS_PLAINTEXT,
} gvm_ldap_tls_mode_t;

typedef enum
{
  GVM_LDAP_SUCCESS = 0,
  GVM_LDAP_INVALID_VALUE,
  GVM_LDAP_INITIALIZE_ERROR,
  GVM_LDAP_OPTION_ERROR,
  GVM_LDAP_TLS_ERROR,
  GVM_LDAP_BIND_ERROR,
  GVM_LDAP_SEARCH_ERROR,
  GVM_LDAP_CALLBACK_ERROR,
} gvm_ldap_return_t;

typedef struct {
  gchar *base_dn;         ///< Base DN for the LDAP search.
  int scope;              ///< LDAP search scope (LDAP_SCOPE_BASE,
                          ///    LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE).
  gchar *filter;          ///< LDAP search filter string.
  gchar **attributes;     ///< NULL-terminated attribute list, or NULL for all.
  guint page_size;        ///< Number of entries per page for paged searches.
  guint size_limit;       ///< Maximum number of entries to return.
  guint timeout_seconds;  ///< Timeout for the search in seconds.
} gvm_ldap_search_params_t;

/**
 * @brief LDAP search callback return enumeration.
 *
 * This enumeration defines the possible return values for an LDAP search
 * callback function.
 */
typedef enum
{
  GVM_LDAP_SEARCH_CONTINUE,          /* Continue the search normally. */
  GVM_LDAP_SEARCH_STOP,              /* Terminate the search and return success. */
  GVM_LDAP_SEARCH_CALLBACK_ERROR,    /* Abort the search due to an error in the callback. */
} gvm_ldap_search_callback_return_t;

typedef gvm_ldap_search_callback_return_t (*gvm_ldap_search_callback_t) (
  LDAP *, LDAPMessage *, gpointer);

gvm_ldap_return_t
gvm_ldap_open (LDAP **, const gchar *, gint, const gchar *, gvm_ldap_tls_mode_t,
               guint, guint);

gvm_ldap_return_t
gvm_ldap_bind_simple (LDAP *, const gchar *, const gchar *);

gvm_ldap_return_t
gvm_ldap_search_paged (LDAP *, gvm_ldap_search_params_t *,
                       gvm_ldap_search_callback_t, gpointer);

void
gvm_ldap_close (LDAP *);

gchar *
gvm_ldap_entry_get_dn (LDAP *, LDAPMessage *);

gchar *
gvm_ldap_entry_get_string (LDAP *, LDAPMessage *, const gchar *);

GPtrArray *
gvm_ldap_entry_get_strings (LDAP *, LDAPMessage *, const gchar *);

gvm_ldap_search_params_t *
gvm_ldap_search_params_new (const gchar *, int , const gchar *, gchar **,
                            guint, guint, guint);

void
gvm_ldap_search_params_free (gvm_ldap_search_params_t *);

#endif /* not _GVM_LDAP_GVMLDAP_H */
