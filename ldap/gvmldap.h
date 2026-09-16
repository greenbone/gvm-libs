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

/**
 * @brief LDAP search scope enumeration.
 */
typedef enum
{
  GVM_LDAP_SCOPE_BASE,
  GVM_LDAP_SCOPE_ONELEVEL,
  GVM_LDAP_SCOPE_SUBTREE,
} gvm_ldap_scope_t;

/**
 * @brief LDAP return codes enumeration.
 */
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
  GVM_LDAP_SEARCH_CALLBACK_ERROR,    /* Abort the search due to an error. */
} gvm_ldap_search_callback_return_t;

typedef struct gvm_ldap_connection gvm_ldap_connection_t;
typedef struct gvm_ldap_entry gvm_ldap_entry_t;

/**
 * @brief Parameters for an LDAP search.
 *
 * Instances created using gvm_ldap_search_params_new() own duplicated
 * copies of base_dn, filter and attributes, and must be freed with
 * gvm_ldap_search_params_free().
 *
 */
typedef struct {
  gchar *base_dn;          ///< Base DN for the LDAP search.
  gvm_ldap_scope_t scope;  ///< LDAP search scope (element of gvm_ldap_scope_t)
  gchar *filter;           ///< LDAP search filter string.
  gchar **attributes;      ///< NULL-terminated attribute list, or NULL for all.
  guint page_size;         ///< Number of entries per page for paged searches.
  guint size_limit;        ///< Maximum number of entries to return.
  guint timeout_seconds;   ///< Timeout for the search in seconds.
} gvm_ldap_search_params_t;

/**
 * @brief LDAP search callback function.
 *        The entry passed to the callback is borrowed and
 *        only valid for the duration of the callback.
 */
typedef gvm_ldap_search_callback_return_t (*gvm_ldap_search_callback_t) (
  gvm_ldap_entry_t *, gpointer);


gvm_ldap_return_t
gvm_ldap_open (gvm_ldap_connection_t **, const gchar *, gint, const gchar *,
               gvm_ldap_tls_mode_t, guint, guint);

gvm_ldap_return_t
gvm_ldap_bind_simple (gvm_ldap_connection_t *, const gchar *, const gchar *);

gvm_ldap_return_t
gvm_ldap_search_paged (gvm_ldap_connection_t *,
                       const gvm_ldap_search_params_t *,
                       gvm_ldap_search_callback_t,
                       gpointer);

void
gvm_ldap_close (gvm_ldap_connection_t *);

gchar *
gvm_ldap_entry_get_dn (gvm_ldap_entry_t *);

gchar *
gvm_ldap_entry_get_string (gvm_ldap_entry_t *, const gchar *);

GPtrArray *
gvm_ldap_entry_get_strings (gvm_ldap_entry_t *, const gchar *);

gvm_ldap_search_params_t *
gvm_ldap_search_params_new (const gchar *, gvm_ldap_scope_t, const gchar *,
                            gchar **, guint, guint, guint);

void
gvm_ldap_search_params_free (gvm_ldap_search_params_t *);

#endif /* not _GVM_LDAP_GVMLDAP_H */
