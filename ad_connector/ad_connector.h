/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file ad_connector.h
 * @brief Active Directory connector interface.
 *
 */

#ifndef _GVM_AD_CONNECTOR_AD_CONNECTOR_H
#define _GVM_AD_CONNECTOR_AD_CONNECTOR_H

#include <glib.h>

/**
 * @brief LDAP connection option enumeration.
 */
typedef enum
{
  AD_CONNECTOR_OPT_HOST,         /**< non-empty host/IP without port */
  AD_CONNECTOR_OPT_PORT,         /**< LDAP server port, 0 uses the
                                      TLS mode default */
  AD_CONNECTOR_OPT_TLS_MODE,     /**< Instance of ad_connector_tls_mode_t */
  AD_CONNECTOR_OPT_CA_CERT_FILE, /**< Optional CA certificate path */
  AD_CONNECTOR_OPT_BIND_DN, /**< Non-empty bind name/DN for the LDAP connection
                             */
  AD_CONNECTOR_OPT_NETWORK_TIMEOUT,   /**< Network timeout (seconds),
                                           0 for no explicit timeout/default LDAP
                                         behavior*/
  AD_CONNECTOR_OPT_OPERATION_TIMEOUT, /**< Operation timeout (seconds),
                                           0 for no explicit timeout/default
                                         LDAP behavior */
} ad_connector_opt_t;

typedef enum
{
  AD_CONNECTOR_OK = 0,
  AD_CONNECTOR_INVALID_OPT,
  AD_CONNECTOR_INVALID_VALUE,
  AD_CONNECTOR_CONNECTION_ERROR,
  AD_CONNECTOR_BIND_ERROR,
  AD_CONNECTOR_SEARCH_ERROR,
  AD_CONNECTOR_RESULT_ERROR,
} ad_connector_return_t;

typedef enum
{
  AD_CONNECTOR_TLS_LDAPS,
  AD_CONNECTOR_TLS_STARTTLS,
} ad_connector_tls_mode_t;

typedef enum
{
  AD_SEARCH_CONFIG_OPT_BASE_DN,   /**< Base distinguished name for the search */
  AD_SEARCH_CONFIG_OPT_SCOPE,     /**< Search scope. Instance of
                                     ad_connector_search_scope_t */
  AD_SEARCH_CONFIG_OPT_PAGE_SIZE, /**< Page size for the search results.
                                       0 for GVM_LDAP_DEFAULT_PAGE_SIZE*/
  AD_SEARCH_CONFIG_OPT_SIZE_LIMIT,   /**< Size limit for the search results */
  AD_SEARCH_CONFIG_OPT_TIME_LIMIT,   /**< Time limit for the search results */
  AD_SEARCH_CONFIG_OPT_MAX_RESULTS,  /**< Maximum number of results to return */
  AD_SEARCH_CONFIG_OPT_OBJECT_TYPES, /**< Object types to search for. Bitmask of
                                        ad_object_type_t */
  AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES, /**< Extra attributes to retrieve from
                                            the LDAP entries */
  AD_SEARCH_CONFIG_OPT_INCLUDE_DISABLED_COMPUTERS, /**< Whether to include
                                                      disabled computer accounts
                                                      in the search */
} ad_search_config_opt_t;

typedef enum
{
  AD_CONNECTOR_SEARCH_SCOPE_BASE,     /**< Base object only */
  AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL, /**< One level below the base object */
  AD_CONNECTOR_SEARCH_SCOPE_SUBTREE /**< Entire subtree below the base object */
} ad_connector_search_scope_t;

/**
 * @brief AD object type bitmask.
 *
 * Values can be ORed together. Use AD_OBJECT_TYPE_ALL for all supported types.
 */
typedef enum
{
  AD_OBJECT_TYPE_OU = 1 << 0,
  AD_OBJECT_TYPE_COMPUTER = 1 << 1,
  AD_OBJECT_TYPE_GROUP = 1 << 2,
} ad_object_type_t;

#define AD_OBJECT_TYPE_ALL \
  (AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_COMPUTER | AD_OBJECT_TYPE_GROUP)

typedef struct
{
  ad_object_type_t type;     /**< Object type */
  gchar *name;               /**< Object name */
  gchar *distinguished_name; /**< Distinguished name */
  gchar *parent_dn;          /**< Parent distinguished name */

  GHashTable *attributes; /**< Object attributes */
} ad_object_t;

typedef enum
{
  AD_OBJECT_CALLBACK_CONTINUE, /**< Continue processing objects */
  AD_OBJECT_CALLBACK_ERROR,    /**< An error occurred during processing */
} ad_object_callback_result_t;

/**
 * The object passed to the callback is owned by the connector and is valid
 * only for the duration of the callback.
 */
typedef ad_object_callback_result_t (*ad_object_callback_t) (
  ad_object_t *object, gpointer user_data);

typedef struct ad_connector *ad_connector_t;
typedef struct ad_search_config *ad_search_config_t;

typedef struct
{
  guint emitted;      /**< Objects accepted by the callback. */
  gboolean truncated; /**< TRUE if max_results stopped the search early. */
} ad_object_search_result_t;

ad_search_config_t
ad_search_config_new (void);

ad_connector_return_t
ad_search_config_builder (ad_search_config_t, ad_search_config_opt_t,
                          const void *);

void ad_search_config_free (ad_search_config_t);

ad_connector_t
ad_connector_new (void);

ad_connector_return_t
ad_connector_builder (ad_connector_t, ad_connector_opt_t, const void *);

void ad_connector_free (ad_connector_t);

ad_connector_return_t
ad_connector_connect (ad_connector_t, const gchar *);

ad_connector_return_t
ad_connector_search_objects (ad_connector_t, const ad_search_config_t,
                             ad_object_callback_t, gpointer,
                             ad_object_search_result_t *);

#endif /* not _GVM_AD_CONNECTOR_AD_CONNECTOR_H */