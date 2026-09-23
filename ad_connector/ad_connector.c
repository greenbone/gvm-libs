/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file ad_connector.c
 * @brief Active Directory connector implementation for managing
 *        connections and queries.
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm ad_connector"

#include "ad_connector.h"

#include "../ldap/gvmldap.h"

#include <string.h>

#define AD_CONNECTOR_DEFAULT_MAX_RESULTS 1000

/**
 * @brief Struct holding the data for connecting with Active Directory server.
 */
struct ad_connector
{
  gvm_ldap_connection_t *ldap_connection; /**< LDAP connection. */
  gchar *ldap_host;                       /**< LDAP server hostname or IP.
                                               Port not included */
  gint ldap_port;                         /**< LDAP port number or 0 for default
                                               (389 for LDAP, 636 for LDAPS). */
  ad_connector_tls_mode_t tls_mode; /**< TLS mode to use for the connection. */
  gchar *cacert_file;               /**< CA Certificate, or NULL. */
  gchar *bind_dn;                   /**< Distinguished Name (DN) to bind as. */
  guint network_timeout;            /**< Network timeout in seconds. */
  guint operation_timeout;          /**< Operation timeout in seconds. */
};

struct ad_search_config
{
  gchar *base_dn;                    /**< Base Distinguished Name (DN)
                                           for the LDAP search. */
  ad_connector_search_scope_t scope; /**< Search scope for the LDAP query. */
  ad_object_type_t object_types;     /**< Bitmask of object types to include
                                          in the search. */
  guint page_size;                   /**< Page size for paged LDAP searches.
                                          or 0 for GVM_LDAP_DEFAULT_PAGE_SIZE */
  guint ldap_size_limit;             /**< Client-requested cap on the number
                                          of LDAP search results after which
                                          LDAP_SIZELIMIT_EXCEEDED
                                          is returned.
                                          0 for no client-imposed limit */
  guint ldap_time_limit;             /**< Search timeout in seconds.
                                          This is client-requested and may
                                          be overriden by the server. */
  guint max_results; /**< Maximum number of search results to return
                          or 0 for no limit. */
  gchar
    *extra_attributes; /**< Optional additional LDAP attributes to retrieve. */

  gboolean include_disabled_computers; /**< Whether to include disabled accounts
                                          in the search results. */
};

typedef struct
{
  guint max_results;  /**< Maximum number of search results to return. */
  guint emitted;      /**< Number of search results emitted to the callback. */
  gboolean truncated; /**< TRUE if the search was truncated due
                           to max_results limit. */
  gchar **attributes; /**< List of LDAP attributes to retrieve. */
  ad_object_callback_t
    callback;         /**< Callback function for processing search results. */
  gpointer user_data; /**< User-defined data passed to the callback. */
} ad_search_context_t;

/**
 * @brief List of general LDAP attributes for Active Directory searches.
 */
static const gchar *ad_object_core_attributes[] = {
  "objectClass", "objectCategory", "name", "description", "cn", NULL};

/**
 * @brief Organizational Unit (OU) LDAP attributes.
 */
static const gchar *ad_ou_attributes[] = {"ou", NULL};

/**
 * @brief Computer LDAP attributes.
 */
static const gchar *ad_computer_attributes[] = {"dNSHostName",
                                                "sAMAccountName",
                                                "operatingSystem",
                                                "operatingSystemVersion",
                                                "servicePrincipalName",
                                                "userAccountControl",
                                                NULL};

/**
 * @brief Group LDAP attributes.
 */
static const gchar *ad_group_attributes[] = {"sAMAccountName", "displayName",
                                             "groupType", "memberOf", NULL};

/**
 * @brief Create a new Active Directory connector instance.
 *
 * The connector defaults to LDAPS, port 0, no CA certificate file,
 * no bind DN, and zero network/operation timeouts.
 *
 * Port 0 lets the LDAP layer choose the default port for the
 * selected TLS mode.
 *
 * @return A newly allocated connector. Free with ad_connector_free().
 */
ad_connector_t
ad_connector_new (void)
{
  ad_connector_t connector = g_malloc0 (sizeof (struct ad_connector));
  connector->tls_mode = AD_CONNECTOR_TLS_LDAPS;
  return connector;
}

/**
 * @brief Helper function to set a non-negative value.
 *
 * @param value   The value to set.
 * @param result  Pointer to the variable where the result will be stored.
 *
 * @return An error code indicating the result of the operation.
 */
static ad_connector_return_t
set_non_negative_value (const void *value, guint *result)
{
  gint int_value = *((const gint *) value);

  if (int_value < 0)
    return AD_CONNECTOR_INVALID_VALUE;

  *result = (guint) int_value;
  return AD_CONNECTOR_OK;
}

/**
 * @brief Helper function to set a non-empty string value.
 *
 * @param value   The string value to set.
 * @param result  Pointer to the variable where the result will be stored.
 *
 * @return An error code indicating the result of the operation.
 */
static ad_connector_return_t
set_non_empty_string_value (const void *value, gchar **result)
{
  if (value == NULL || *((const gchar *) value) == '\0')
    return AD_CONNECTOR_INVALID_VALUE;

  g_free (*result);
  *result = g_strdup ((const gchar *) value);
  return AD_CONNECTOR_OK;
}

/**
 * @brief Sets one connection option on an AD connector.
 *
 * String values are copied. Numeric values are passed as pointers to gint.
 * TLS mode is passed as a pointer to ad_connector_tls_mode_t.
 *
 * @param connector  Connector to configure.
 * @param opt        Option to set.
 * @param val        Option value.
 *
 * @return AD_CONNECTOR_OK on success, AD_CONNECTOR_INVALID_OPT for unknown
 *         options, AD_CONNECTOR_INVALID_VALUE for invalid input, or
 *         AD_CONNECTOR_CONNECTION_ERROR if the connector is already connected.
 */
ad_connector_return_t
ad_connector_builder (ad_connector_t connector, ad_connector_opt_t opt,
                      const void *val)
{
  if (connector == NULL)
    return AD_CONNECTOR_INVALID_VALUE;

  if (connector->ldap_connection)
    return AD_CONNECTOR_CONNECTION_ERROR;

  if (val == NULL && opt != AD_CONNECTOR_OPT_CA_CERT_FILE)
    return AD_CONNECTOR_INVALID_VALUE;

  switch (opt)
    {
    case AD_CONNECTOR_OPT_HOST:
      return set_non_empty_string_value (val, &connector->ldap_host);
    case AD_CONNECTOR_OPT_PORT:
      {
        gint port = *((const gint *) val);
        if (port < 0 || port > 65535)
          return AD_CONNECTOR_INVALID_VALUE;
        connector->ldap_port = port;
        break;
      }
    case AD_CONNECTOR_OPT_TLS_MODE:
      {
        ad_connector_tls_mode_t tls_mode =
          *((const ad_connector_tls_mode_t *) val);
        if (tls_mode != AD_CONNECTOR_TLS_LDAPS
            && tls_mode != AD_CONNECTOR_TLS_STARTTLS)
          return AD_CONNECTOR_INVALID_VALUE;
        connector->tls_mode = tls_mode;
        break;
      }
    case AD_CONNECTOR_OPT_CA_CERT_FILE:
      g_free (connector->cacert_file);
      connector->cacert_file = val ? g_strdup ((const gchar *) val) : NULL;
      break;
    case AD_CONNECTOR_OPT_BIND_DN:
      return set_non_empty_string_value (val, &connector->bind_dn);
    case AD_CONNECTOR_OPT_NETWORK_TIMEOUT:
      return set_non_negative_value (val, &connector->network_timeout);
    case AD_CONNECTOR_OPT_OPERATION_TIMEOUT:
      return set_non_negative_value (val, &connector->operation_timeout);
    default:
      return AD_CONNECTOR_INVALID_OPT;
    }

  return AD_CONNECTOR_OK;
}

/**
 * @brief Creates a new AD search configuration with default values.
 *
 * The configuration defaults to:
 *   - object_types: AD_OBJECT_TYPE_ALL
 *   - scope: AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL
 *   - max_results: AD_CONNECTOR_DEFAULT_MAX_RESULTS
 *   - page_size: 0
 *   - include_disabled_computers: TRUE
 *
 * @return A newly allocated search configuration. Free with
 *         ad_search_config_free().
 */
ad_search_config_t
ad_search_config_new (void)
{
  ad_search_config_t config = g_malloc0 (sizeof (struct ad_search_config));

  config->object_types = AD_OBJECT_TYPE_ALL;
  config->scope = AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL;
  config->max_results = AD_CONNECTOR_DEFAULT_MAX_RESULTS;
  config->page_size = 0;
  config->include_disabled_computers = TRUE;

  return config;
}

/**
 * @brief Checks if the provided object type flags are valid.
 *
 * @param object_types  The object type flags to validate.
 *
 * @return TRUE if the flags are valid, FALSE otherwise.
 */
static gboolean
ad_object_type_flags_are_valid (ad_object_type_t object_types)
{
  return object_types != 0 && (object_types & ~AD_OBJECT_TYPE_ALL) == 0;
}

/**
 * @brief Sets one option on an AD search configuration.
 *
 * String values are copied. Numeric values are passed as pointers to gint.
 * Scope and object types are passed as pointers to their respective enum
 * types.
 *
 * @param config  Search configuration to modify.
 * @param opt     Option to set.
 * @param value   Option value.
 *
 * @return AD_CONNECTOR_OK on success, AD_CONNECTOR_INVALID_OPT for unknown
 *         options, or AD_CONNECTOR_INVALID_VALUE for invalid input.
 */
ad_connector_return_t
ad_search_config_builder (ad_search_config_t config, ad_search_config_opt_t opt,
                          const void *value)
{
  if (!config)
    return AD_CONNECTOR_INVALID_VALUE;

  if (!value && opt != AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES)
    return AD_CONNECTOR_INVALID_VALUE;

  switch (opt)
    {
    case AD_SEARCH_CONFIG_OPT_BASE_DN:
      return set_non_empty_string_value (value, &config->base_dn);
    case AD_SEARCH_CONFIG_OPT_SCOPE:
      {
        ad_connector_search_scope_t scope =
          *((const ad_connector_search_scope_t *) value);
        if (scope != AD_CONNECTOR_SEARCH_SCOPE_BASE
            && scope != AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL
            && scope != AD_CONNECTOR_SEARCH_SCOPE_SUBTREE)
          return AD_CONNECTOR_INVALID_VALUE;
        config->scope = scope;
        break;
      }
    case AD_SEARCH_CONFIG_OPT_OBJECT_TYPES:
      {
        ad_object_type_t object_types = *((const ad_object_type_t *) value);
        if (!ad_object_type_flags_are_valid (object_types))
          return AD_CONNECTOR_INVALID_VALUE;
        config->object_types = object_types;
        break;
      }
    case AD_SEARCH_CONFIG_OPT_PAGE_SIZE:
      return set_non_negative_value (value, &config->page_size);
    case AD_SEARCH_CONFIG_OPT_SIZE_LIMIT:
      return set_non_negative_value (value, &config->ldap_size_limit);
    case AD_SEARCH_CONFIG_OPT_TIME_LIMIT:
      return set_non_negative_value (value, &config->ldap_time_limit);
    case AD_SEARCH_CONFIG_OPT_MAX_RESULTS:
      return set_non_negative_value (value, &config->max_results);
    case AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES:
      g_free (config->extra_attributes);
      config->extra_attributes =
        value ? g_strdup ((const gchar *) value) : NULL;
      break;
    case AD_SEARCH_CONFIG_OPT_INCLUDE_DISABLED_COMPUTERS:
      config->include_disabled_computers = !!*((const gboolean *) value);
      break;
    default:
      return AD_CONNECTOR_INVALID_OPT;
    }

  return AD_CONNECTOR_OK;
}

/**
 * @brief Frees an AD search configuration.
 *
 * @param config Search configuration to free.
 */
void
ad_search_config_free (ad_search_config_t config)
{
  if (config == NULL)
    return;

  g_free (config->base_dn);
  g_free (config->extra_attributes);
  g_free (config);
}

/**
 * @brief Converts the AD connector's TLS mode to the corresponding
 *        GVM LDAP TLS mode.
 *
 * @param connector  The AD connector instance containing the TLS mode.
 * @param tls_mode   Pointer to store the converted GVM LDAP TLS mode.
 *
 * @return AD_CONNECTOR_OK on success, or AD_CONNECTOR_INVALID_VALUE for an
 *         unknown AD TLS mode.
 */
static ad_connector_return_t
get_gvm_ldap_tls_mode (ad_connector_t connector, gvm_ldap_tls_mode_t *tls_mode)
{
  if (!connector || !tls_mode)
    return AD_CONNECTOR_INVALID_VALUE;

  switch (connector->tls_mode)
    {
    case AD_CONNECTOR_TLS_LDAPS:
      *tls_mode = GVM_LDAP_TLS_LDAPS;
      return AD_CONNECTOR_OK;
    case AD_CONNECTOR_TLS_STARTTLS:
      *tls_mode = GVM_LDAP_TLS_STARTTLS;
      return AD_CONNECTOR_OK;
    default:
      g_warning ("%s: Unknown TLS mode %d.", __func__, connector->tls_mode);
      return AD_CONNECTOR_INVALID_VALUE;
    }
}

/**
 * @brief Opens and binds an LDAP connection to the configured AD server.
 *
 * A port value of 0 uses the LDAP layer's default for the selected TLS mode.
 * Calling this function on an already connected connector fails with
 * AD_CONNECTOR_CONNECTION_ERROR.
 *
 * @param connector  AD connector configured with host and bind name.
 * @param password   Non-empty password used for the simple bind.
 *
 * @return AD_CONNECTOR_OK on success, AD_CONNECTOR_INVALID_VALUE for missing
 *         or invalid input/configuration, AD_CONNECTOR_CONNECTION_ERROR for
 *         connection/open failures, or AD_CONNECTOR_BIND_ERROR for bind
 *         failures reported by the LDAP server.
 */
ad_connector_return_t
ad_connector_connect (ad_connector_t connector, const gchar *password)
{
  gvm_ldap_return_t ret;
  ad_connector_return_t connector_ret;
  gvm_ldap_tls_mode_t tls_mode;

  if (!connector || !password || password[0] == '\0')
    return AD_CONNECTOR_INVALID_VALUE;

  if (connector->ldap_connection)
    {
      g_warning ("%s: LDAP connection already established.", __func__);
      return AD_CONNECTOR_CONNECTION_ERROR;
    }

  if (!connector->ldap_host || connector->ldap_host[0] == '\0'
      || !connector->bind_dn || connector->bind_dn[0] == '\0')
    return AD_CONNECTOR_INVALID_VALUE;

  connector_ret = get_gvm_ldap_tls_mode (connector, &tls_mode);
  if (connector_ret != AD_CONNECTOR_OK)
    return connector_ret;

  ret =
    gvm_ldap_open (&connector->ldap_connection, connector->ldap_host,
                   connector->ldap_port, connector->cacert_file, tls_mode,
                   connector->network_timeout, connector->operation_timeout);

  if (ret != GVM_LDAP_SUCCESS)
    {
      g_warning ("%s: Failed to open LDAP connection.", __func__);
      return ret == GVM_LDAP_INVALID_VALUE ? AD_CONNECTOR_INVALID_VALUE
                                           : AD_CONNECTOR_CONNECTION_ERROR;
    }

  ret = gvm_ldap_bind_simple (connector->ldap_connection, connector->bind_dn,
                              password);

  if (ret != GVM_LDAP_SUCCESS)
    {
      g_warning ("%s: Failed to bind to LDAP server.", __func__);
      gvm_ldap_close (connector->ldap_connection);
      connector->ldap_connection = NULL;

      if (ret == GVM_LDAP_INVALID_VALUE)
        return AD_CONNECTOR_INVALID_VALUE;

      return AD_CONNECTOR_BIND_ERROR;
    }

  return AD_CONNECTOR_OK;
}

/**
 * @brief Checks if an LDAP entry has a specific attribute value.
 *
 * @param entry           The LDAP entry to check.
 * @param attribute       The attribute name to look for.
 * @param expected_value  The expected value of the attribute.
 *
 * @return TRUE if the attribute has the expected value, FALSE otherwise.
 */
static gboolean
ad_ldap_entry_has_value (gvm_ldap_entry_t *entry, const gchar *attribute,
                         const gchar *expected_value)
{
  GPtrArray *values;
  gboolean found = FALSE;
  guint index;

  if (!entry || !attribute || !expected_value)
    return FALSE;

  values = gvm_ldap_entry_get_strings (entry, attribute);
  if (!values)
    return FALSE;

  for (index = 0; index < values->len; index++)
    {
      const gchar *value = g_ptr_array_index (values, index);

      if (value && g_ascii_strcasecmp (value, expected_value) == 0)
        {
          found = TRUE;
          break;
        }
    }

  g_ptr_array_free (values, TRUE);
  return found;
}

/**
 * @brief Checks if an LDAP entry represents an organizational unit (OU).
 *
 * @param entry  The LDAP entry to check.
 *
 * @return TRUE if the entry is an OU, FALSE otherwise.
 */
static gboolean
entry_is_ou (gvm_ldap_entry_t *entry)
{
  return ad_ldap_entry_has_value (entry, "objectClass", "organizationalUnit");
}

/**
 * @brief Checks if an LDAP entry represents a computer.
 *
 * @param entry  The LDAP entry to check.
 *
 * @return TRUE if the entry is a computer, FALSE otherwise.
 */
static gboolean
entry_is_computer (gvm_ldap_entry_t *entry)
{
  return ad_ldap_entry_has_value (entry, "objectClass", "computer");
}

/**
 * @brief Checks if an LDAP entry represents a group.
 *
 * @param entry  The LDAP entry to check.
 *
 * @return TRUE if the entry is a group, FALSE otherwise.
 */
static gboolean
entry_is_group (gvm_ldap_entry_t *entry)
{
  return ad_ldap_entry_has_value (entry, "objectClass", "group");
}

/**
 * @brief Frees the memory allocated for attribute values.
 *
 * @param data  The GPtrArray to free.
 */
static void
ad_attribute_values_free (gpointer data)
{
  if (data)
    g_ptr_array_free (data, TRUE);
}

/**
 * @brief Extracts the parent distinguished name (DN) from a given DN.
 *
 * @param dn  The distinguished name to extract the parent DN from.
 *
 * @return A newly allocated string containing the parent DN
 *         or NULL otherwise.
 */
static gchar *
get_parent_dn_from_dn (const gchar *dn)
{
  const gchar *current;
  gboolean escaped = FALSE;

  if (!dn || dn[0] == '\0')
    return NULL;

  for (current = dn; *current; current++)
    {
      if (escaped)
        {
          escaped = FALSE;
          continue;
        }

      if (*current == '\\')
        {
          escaped = TRUE;
          continue;
        }

      if (*current == ',')
        {
          const gchar *parent = current + 1;

          while (g_ascii_isspace (*parent))
            parent++;

          return parent[0] ? g_strdup (parent) : NULL;
        }
    }

  return NULL;
}

/**
 * @brief Frees the resources associated with an AD object.
 *
 * @param object The AD object to free.
 */
static void
ad_object_free (ad_object_t *object)
{
  if (object == NULL)
    return;

  g_free (object->name);
  g_free (object->distinguished_name);
  g_free (object->parent_dn);

  if (object->attributes)
    g_hash_table_destroy (object->attributes);

  g_free (object);
}

/**
 * @brief Creates an AD object structure from an LDAP entry.
 *
 * @param ld          The LDAP connection.
 * @param entry       The LDAP entry to extract information from.
 * @param attributes  The list of attributes to retrieve from the entry.
 *
 * @return A newly allocated ad_object_t structure, or NULL on failure.
 */
static ad_object_t *
ad_object_from_ldap_entry (gvm_ldap_entry_t *entry, gchar **attributes)
{
  ad_object_t *object;
  ad_object_type_t type;

  if (entry_is_ou (entry))
    type = AD_OBJECT_TYPE_OU;
  else if (entry_is_computer (entry))
    type = AD_OBJECT_TYPE_COMPUTER;
  else if (entry_is_group (entry))
    type = AD_OBJECT_TYPE_GROUP;
  else
    return NULL;

  object = g_malloc0 (sizeof (ad_object_t));
  object->type = type;
  object->distinguished_name = gvm_ldap_entry_get_dn (entry);
  object->name = gvm_ldap_entry_get_string (entry, "name");

  if (!object->distinguished_name || !object->name)
    {
      ad_object_free (object);
      return NULL;
    }

  object->parent_dn = get_parent_dn_from_dn (object->distinguished_name);

  object->attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                              ad_attribute_values_free);

  for (int i = 0; attributes && attributes[i]; i++)
    {
      GPtrArray *values;

      values = gvm_ldap_entry_get_strings (entry, attributes[i]);
      if (values)
        g_hash_table_insert (object->attributes, g_strdup (attributes[i]),
                             values);
    }

  return object;
}

/**
 * @brief LDAP search callback that converts entries to AD objects.
 *
 * Converts supported LDAP entries to temporary AD objects and passes them to
 *  the user callback stored in the search context.
 *  The AD object is valid only for the duration of the user callback.
 *
 * @param entry    The LDAP entry to process.
 * @param context  ad_search_context_t used to track callback state.
 *
 * @return GVM_LDAP_SEARCH_CONTINUE to continue, GVM_LDAP_SEARCH_STOP when the
 *         configured result limit is reached, or
 *         GVM_LDAP_SEARCH_CALLBACK_ERROR when the user callback reports an
 *         error or returns an unknown result.
 */
static gvm_ldap_search_callback_return_t
ad_search_ldap_entry_callback (gvm_ldap_entry_t *entry, gpointer context)
{
  ad_search_context_t *ctx = context;
  ad_object_t *object;
  ad_object_callback_result_t result;

  if (!ctx || !ctx->callback)
    return GVM_LDAP_SEARCH_CALLBACK_ERROR;

  object = ad_object_from_ldap_entry (entry, ctx->attributes);
  if (!object)
    {
      g_warning ("Failed to create ad_object from LDAP entry.");
      return GVM_LDAP_SEARCH_CONTINUE;
    }

  if (ctx->max_results > 0 && ctx->emitted >= ctx->max_results)
    {
      ctx->truncated = TRUE;
      ad_object_free (object);
      return GVM_LDAP_SEARCH_STOP;
    }

  result = ctx->callback (object, ctx->user_data);
  ad_object_free (object);

  switch (result)
    {
    case AD_OBJECT_CALLBACK_CONTINUE:
      ctx->emitted++;
      return GVM_LDAP_SEARCH_CONTINUE;

    case AD_OBJECT_CALLBACK_ERROR:
      return GVM_LDAP_SEARCH_CALLBACK_ERROR;
    default:
      break;
    }

  return GVM_LDAP_SEARCH_CALLBACK_ERROR;
}

/**
 * @brief Builds the LDAP search filter string for computer objects.
 *
 * @param include_disabled_computers  Whether to include disabled computer
 *                                    accounts.
 *
 * @return A newly allocated string containing the LDAP filter.
 *         The caller is responsible for freeing it.
 */
static gchar *
ad_connector_build_computer_filter (gboolean include_disabled_computers)
{
  if (include_disabled_computers)
    return g_strdup ("(&(objectCategory=computer)"
                     "(objectClass=computer))");

  return g_strdup ("(&(objectCategory=computer)"
                   "(objectClass=computer)"
                   "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
}

/**
 * @brief Builds the LDAP search filter string for the given
 *        search configuration.
 *
 * @param config  Pointer to the search configuration instance.
 *
 * @return A newly allocated LDAP filter string or NULL on error.
 *         Free with g_free().
 */
static gchar *
ad_connector_build_search_filter (ad_search_config_t config)
{
  GPtrArray *clauses;
  GString *filter;
  gchar *result;
  guint index;

  if (!config || !config->object_types
      || !ad_object_type_flags_are_valid (config->object_types))
    return NULL;

  clauses = g_ptr_array_new_with_free_func (g_free);

  if (config->object_types & AD_OBJECT_TYPE_OU)
    g_ptr_array_add (clauses, g_strdup ("(&(objectCategory=organizationalUnit)"
                                        "(objectClass=organizationalUnit))"));

  if (config->object_types & AD_OBJECT_TYPE_COMPUTER)
    g_ptr_array_add (clauses, ad_connector_build_computer_filter (
                                config->include_disabled_computers));

  if (config->object_types & AD_OBJECT_TYPE_GROUP)
    g_ptr_array_add (clauses, g_strdup ("(&(objectCategory=group)"
                                        "(objectClass=group))"));

  if (clauses->len == 0)
    {
      g_ptr_array_free (clauses, TRUE);
      return NULL;
    }

  if (clauses->len == 1)
    {
      result = g_strdup (g_ptr_array_index (clauses, 0));
      g_ptr_array_free (clauses, TRUE);
      return result;
    }

  filter = g_string_new ("(|");

  for (index = 0; index < clauses->len; index++)
    g_string_append (filter, g_ptr_array_index (clauses, index));

  g_string_append_c (filter, ')');

  g_ptr_array_free (clauses, TRUE);

  return g_string_free (filter, FALSE);
}

/**
 * @brief Adds a unique attribute to the given attribute array.
 *
 * @param attributes  Pointer to the attribute array.
 * @param attribute   The attribute to add.
 */
static void
ad_attribute_array_add_unique (GPtrArray *attributes, const gchar *attribute)
{
  if (!attributes || attribute[0] == '\0')
    return;

  for (guint i = 0; i < attributes->len; i++)
    {
      if (g_ascii_strcasecmp (attribute, g_ptr_array_index (attributes, i))
          == 0)
        {
          g_warning ("%s: Duplicate attribute '%s' ignored", __func__,
                     attribute);
          return;
        }
    }

  g_ptr_array_add (attributes, g_strdup (attribute));
}

/**
 * @brief Adds a list of attributes to the given attribute array.
 *
 * @param attributes      Pointer to the attribute array.
 * @param attribute_list  NULL-terminated array of attribute names to add.
 */
static void
ad_attribute_array_add_list (GPtrArray *attributes,
                             const gchar *const *attribute_list)
{
  if (!attribute_list || !attribute_list[0])
    return;

  for (guint i = 0; attribute_list[i]; i++)
    ad_attribute_array_add_unique (attributes, attribute_list[i]);
}

/**
 * @brief Adds extra attributes to the given attribute array,
 *        Duplicate attributes are ignored.
 *
 * @param attributes        Pointer to the attribute array.
 * @param extra_attributes  Comma-separated list of extra attributes to add.
 */
static void
ad_attribute_array_add_extra_attributes (GPtrArray *attributes,
                                         const gchar *extra_attributes)
{
  if (!extra_attributes || extra_attributes[0] == '\0')
    return;

  gchar **split = g_strsplit (extra_attributes, ",", -1);

  for (int i = 0; split[i] != NULL; i++)
    {
      gchar *attribute = g_strstrip (split[i]);

      ad_attribute_array_add_unique (attributes, attribute);
    }

  g_strfreev (split);
}

/**
 * @brief Builds the LDAP attributes list for the given search configuration.
 *        Returns an array with the default attributes based on the object
 *        types and any extra attributes specified in the search configuration.
 *
 * @param search_config  Pointer to the search configuration instance.
 *
 * @return A newly allocated, NULL-terminated array of attribute names.
 *         or NULL on error. The caller must free it with g_strfreev().
 */
static gchar **
ad_connector_build_attributes (ad_search_config_t search_config)
{
  if (!search_config)
    return NULL;

  GPtrArray *attributes = g_ptr_array_new_with_free_func (g_free);

  ad_attribute_array_add_list (attributes, ad_object_core_attributes);

  if (search_config->object_types & AD_OBJECT_TYPE_COMPUTER)
    ad_attribute_array_add_list (attributes, ad_computer_attributes);

  if (search_config->object_types & AD_OBJECT_TYPE_OU)
    ad_attribute_array_add_list (attributes, ad_ou_attributes);

  if (search_config->object_types & AD_OBJECT_TYPE_GROUP)
    ad_attribute_array_add_list (attributes, ad_group_attributes);

  ad_attribute_array_add_extra_attributes (attributes,
                                           search_config->extra_attributes);

  g_ptr_array_add (attributes, NULL);
  return (gchar **) g_ptr_array_free (attributes, FALSE);
}

/**
 * @brief Converts an AD filter scope to the corresponding LDAP search scope.
 *
 * @param scope  The AD filter scope to convert.
 *
 * @return The corresponding LDAP search scope.
 */
static gvm_ldap_scope_t
get_ldap_search_scope (ad_connector_search_scope_t scope)
{
  switch (scope)
    {
    case AD_CONNECTOR_SEARCH_SCOPE_BASE:
      return GVM_LDAP_SCOPE_BASE;
    case AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL:
      return GVM_LDAP_SCOPE_ONELEVEL;
    case AD_CONNECTOR_SEARCH_SCOPE_SUBTREE:
      return GVM_LDAP_SCOPE_SUBTREE;
    default:
      g_warning ("%s: Unknown filter scope %d. Defaulting to onelevel scope.",
                 __func__, scope);
      return GVM_LDAP_SCOPE_ONELEVEL;
    }
}

/**
 * @brief Searches for AD objects in Active Directory.
 *
 * Performs a paged LDAP search using the given configuration. For each
 * supported AD object found, the callback is invoked with an ad_object_t
 * that is valid only for the duration of the callback.
 *
 * If max_results is reached, the search stops early, returns
 * AD_CONNECTOR_OK, and sets result->truncated to TRUE when result is
 * provided.
 *
 * @param connector      Connected AD connector instance.
 * @param search_config  Search configuration to use.
 * @param callback       Callback invoked for each AD object found.
 * @param user_data      User data passed to the callback.
 * @param result         Optional search metadata.
 *                       emitted is the number of objects whose calllback
 *                       returned AD_OBJECT_CALLBACK_CONTINUE.
 *
 * @return AD_CONNECTOR_OK on success, AD_CONNECTOR_RESULT_ERROR if the
 *         callback reports an error, AD_CONNECTOR_SEARCH_ERROR for LDAP
 *         search failures, or another error code otherwise.
 */
ad_connector_return_t
ad_connector_search_objects (ad_connector_t connector,
                             const ad_search_config_t search_config,
                             ad_object_callback_t callback, gpointer user_data,
                             ad_object_search_result_t *result)
{
  gvm_ldap_search_params_t *search_params;
  int ret;

  if (!connector || !callback || !search_config)
    return AD_CONNECTOR_INVALID_VALUE;

  if (!connector->ldap_connection)
    {
      g_warning ("%s: Search requires an established LDAP connection.",
                 __func__);
      return AD_CONNECTOR_CONNECTION_ERROR;
    }

  if (result)
    memset (result, 0, sizeof (ad_object_search_result_t));

  gchar *filter = ad_connector_build_search_filter (search_config);
  if (!filter)
    {
      g_warning ("%s: Failed to build LDAP filter.", __func__);
      return AD_CONNECTOR_INVALID_VALUE;
    }
  gchar **attributes = ad_connector_build_attributes (search_config);
  if (!attributes)
    {
      g_warning ("%s: Failed to build LDAP attributes list.", __func__);
      g_free (filter);
      return AD_CONNECTOR_INVALID_VALUE;
    }

  gvm_ldap_scope_t scope = get_ldap_search_scope (search_config->scope);

  search_params = gvm_ldap_search_params_new (
    search_config->base_dn, scope, filter, attributes, search_config->page_size,
    search_config->ldap_size_limit, search_config->ldap_time_limit);
  if (!search_params)
    {
      g_strfreev (attributes);
      g_free (filter);
      return AD_CONNECTOR_INVALID_VALUE;
    }

  g_free (filter);

  ad_search_context_t context = {.callback = callback,
                                 .user_data = user_data,
                                 .emitted = 0,
                                 .max_results = search_config->max_results,
                                 .attributes = attributes,
                                 .truncated = FALSE};

  ret = gvm_ldap_search_paged (connector->ldap_connection, search_params,
                               ad_search_ldap_entry_callback, &context);

  if (result)
    {
      result->emitted = context.emitted;
      result->truncated = context.truncated;
    }

  g_strfreev (attributes);
  gvm_ldap_search_params_free (search_params);

  if (ret == GVM_LDAP_CALLBACK_ERROR)
    return AD_CONNECTOR_RESULT_ERROR;

  if (ret != GVM_LDAP_SUCCESS)
    return AD_CONNECTOR_SEARCH_ERROR;

  return AD_CONNECTOR_OK;
}

/**
 * @brief Frees the AD connector instance.
 *
 * This function closes the LDAP connection if it is open.
 *
 * @param connector  The AD connector instance to free.
 */
void
ad_connector_free (ad_connector_t connector)
{
  if (connector == NULL)
    return;

  if (connector->ldap_connection != NULL)
    {
      gvm_ldap_close (connector->ldap_connection);
    }

  g_free (connector->ldap_host);
  g_free (connector->cacert_file);
  g_free (connector->bind_dn);

  g_free (connector);
}