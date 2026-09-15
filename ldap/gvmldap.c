/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file gvmldap.c
 * @brief LDAP utility functions built on OpenLDAP.
 *
 * This module provides an abstraction layer over OpenLDAP to simplify LDAP
 * operations. It supports:
 *
 * - Support for StartTLS and LDAPS connections.
 * - Synchronous LDAP operations.
 * - LDAP authentication and binding.
 * - Handling of LDAP search.
 *
 */

#include "gvmldap.h"
#include <string.h>

#define LDAP_DEFAULT_PORT 389
#define LDAPS_DEFAULT_PORT 636

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm ldap"

/*
 * @brief Build an LDAP URI string based on the host, port, and TLS mode.
 *
 * @param ldap_host  LDAP server hostname or IP address.
 * @param port       LDAP server port, or 0 to use the default
 *                   port for the selected TLS mode.
 * @param tls_mode   TLS mode to use (LDAPS, STARTTLS, or PLAINTEXT).
 *
 * @return Newly allocated string containing the LDAP URI.
 *         Caller must free it with g_free().
*/
static gchar *
ldap_build_uri (const gchar *ldap_host, gint port, gvm_ldap_tls_mode_t tls_mode)
{
  const gchar *scheme;
  gint ldap_port;

  scheme = (tls_mode == GVM_LDAP_TLS_LDAPS) ? "ldaps" : "ldap";

  ldap_port = (port > 0) ? port : ((tls_mode == GVM_LDAP_TLS_LDAPS)
                                  ? LDAPS_DEFAULT_PORT
                                  : LDAP_DEFAULT_PORT);

  /* IPv6 address */
  if (strchr(ldap_host, ':') != NULL && ldap_host[0] != '[')
    return g_strdup_printf ("%s://[%s]:%d", scheme, ldap_host, ldap_port);

  return g_strdup_printf ("%s://%s:%d", scheme, ldap_host, ldap_port);
}

/**
 * @brief Set LDAP timeout option.
 *
 * @param ldap              LDAP connection.
 * @param option            LDAP option to set (e.g., LDAP_OPT_NETWORK_TIMEOUT).
 * @param timeout_seconds   Timeout value in seconds or 0 to use default (infinite).
 *
 * @return LDAP_OPT_SUCCESS on success, or an LDAP error code on failure.
 */
static int
ldap_set_timeout_option (LDAP *ldap, int option,
                         guint timeout_seconds)
{
  struct timeval tv;

  if (timeout_seconds == 0)
    return LDAP_OPT_SUCCESS;

  tv.tv_sec = timeout_seconds;
  tv.tv_usec = 0;

  return ldap_set_option (ldap, option, &tv);
}

/*
 * @brief Configure TLS options for an LDAP connection.
 *
 * @param ldap              LDAP connection.
 * @param ca_cert_file      Path to the CA certificate file for TLS, can be NULL.
 *
 * @return 0 on success, -1 on failure.
*/
static int
ldap_configure_tls (LDAP *ldap, const gchar *ca_cert_file)
{
  int require_cert = LDAP_OPT_X_TLS_DEMAND;
  int new_ctx = 0;
  int ret;

  if (!ldap)
    return -1;

  ret = ldap_set_option (ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &require_cert);
  if (ret != LDAP_OPT_SUCCESS)
    return -1;

  if (ca_cert_file && ca_cert_file[0] != '\0')
    {
      ret = ldap_set_option (ldap, LDAP_OPT_X_TLS_CACERTFILE, ca_cert_file);
      if (ret != LDAP_OPT_SUCCESS)
        return -1;
    }

  ret = ldap_set_option (ldap, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
  if (ret != LDAP_OPT_SUCCESS)
    return -1;

  return 0;
}

/**
 * Opens an LDAP connection with the specified parameters.
 *
 * @param ldap               Pointer to the LDAP handle to be initialized.
 * @param host               The LDAP server host.
 * @param port               The LDAP server port, 0 to use the mode's default.
 * @param ca_cert_file       Path to the CA certificate file for TLS.
 * @param tls_mode           The TLS mode to use (PLAINTEXT, STARTTLS, or TLS).
 * @param network_timeout    Network timeout in seconds.
 * @param operation_timeout  Operation timeout in seconds.
 *
 * @return GVM_LDAP_SUCCESS on success, or gvm_ldap_return_t error code otherwise.
 */
gvm_ldap_return_t
gvm_ldap_open (LDAP **ldap,
               const gchar *host,
               gint port,
               const gchar *ca_cert_file,
               gvm_ldap_tls_mode_t tls_mode,
               guint network_timeout,
               guint operation_timeout)
{
  LDAP *ld = NULL;
  gchar *uri = NULL;
  int ldap_ret;
  int ldapv3 = LDAP_VERSION3;

  if (!ldap)
    {
      g_warning ("%s: LDAP handle pointer is required.", __func__);
      return GVM_LDAP_INVALID_VALUE;
    }

  *ldap = NULL;

  if (host == NULL || *host == '\0')
    {
      g_warning ("%s: LDAP host is required.", __func__);
      return GVM_LDAP_INVALID_VALUE;
    }

  if (port < 0 || port > 65535)
    {
      g_warning ("%s: Invalid LDAP port.", __func__);
      return GVM_LDAP_INVALID_VALUE;
    }

  if (tls_mode != GVM_LDAP_TLS_STARTTLS && tls_mode != GVM_LDAP_TLS_LDAPS
      && tls_mode != GVM_LDAP_TLS_PLAINTEXT)
    {
      g_warning ("%s: Invalid TLS mode.", __func__);
      return GVM_LDAP_INVALID_VALUE;
    }

  uri = ldap_build_uri (host, port, tls_mode);

  if (uri == NULL)
    {
      g_warning ("%s: Failed to build LDAP URI.", __func__);
      return GVM_LDAP_INVALID_VALUE;
    }

  ldap_ret = ldap_initialize (&ld, uri);
  g_free (uri);

  if (ld == NULL || ldap_ret != LDAP_SUCCESS)
    {
      g_warning ("%s: Could not initialize LDAP connection: %s",
                 __func__, ldap_err2string (ldap_ret));
      if (ld)
        ldap_unbind_ext_s (ld, NULL, NULL);
      return GVM_LDAP_INITIALIZE_ERROR;
    }

  if (tls_mode != GVM_LDAP_TLS_PLAINTEXT)
    {
      if (ldap_configure_tls (ld, ca_cert_file) != 0)
        {
          g_warning ("%s: Failed to configure LDAP TLS", __func__);
          goto option_error;
        }
    }
  else
    g_warning ("%s: Using LDAP plaintext connection.", __func__);

  ldap_ret = ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &ldapv3);
  if (ldap_ret != LDAP_OPT_SUCCESS)
    {
      g_warning ("%s, Failed to set ldap protocol version to 3: %s.",
                 __func__, ldap_err2string (ldap_ret));
      goto option_error;
    }

  ldap_ret = ldap_set_timeout_option (ld,
                                      LDAP_OPT_NETWORK_TIMEOUT,
                                      network_timeout);
  if (ldap_ret != LDAP_OPT_SUCCESS)
    {
      g_warning ("%s: Failed to set LDAP network timeout: %s",
                 __func__, ldap_err2string (ldap_ret));
      goto option_error;
    }

  ldap_ret = ldap_set_timeout_option (ld,
                                      LDAP_OPT_TIMEOUT,
                                      operation_timeout);
  if (ldap_ret != LDAP_OPT_SUCCESS)
    {
      g_warning ("%s: Failed to set LDAP operation timeout: %s",
                 __func__, ldap_err2string (ldap_ret));
      goto option_error;
    }

  if (tls_mode == GVM_LDAP_TLS_STARTTLS)
    {
      ldap_ret = ldap_start_tls_s (ld, NULL, NULL);
      if (ldap_ret != LDAP_SUCCESS)
        {
          g_warning ("%s: Failed to start LDAP TLS: %s",
                     __func__, ldap_err2string (ldap_ret));
          goto tls_error;
        }
    }

  g_debug ("%s: LDAP connection and configuration successful.", __func__);

  *ldap = ld;
  return GVM_LDAP_SUCCESS;

option_error:
  if (ld)
    ldap_unbind_ext_s (ld, NULL, NULL);
  return GVM_LDAP_OPTION_ERROR;
tls_error:
  if (ld)
    ldap_unbind_ext_s (ld, NULL, NULL);
  return GVM_LDAP_TLS_ERROR;
}

/**
 * @brief Checks if the given LDAP bind DN is valid.
 *
 * @param bind_dn The bind DN to validate.
 *
 * @return TRUE if the bind DN is valid, FALSE otherwise.
 */
static gboolean
ldap_bind_dn_is_valid (const gchar *bind_dn)
{
  LDAPDN dn = NULL;

  if (!bind_dn || bind_dn[0] == '\0')
    return FALSE;

  for (const gchar *p = bind_dn; *p; ++p)
    {
      if (g_ascii_iscntrl (*p))
        return FALSE;
    }

  if (ldap_str2dn (bind_dn, &dn, LDAP_DN_FORMAT_LDAPV3) == LDAP_SUCCESS)
    {
      ldap_dnfree (dn);
      return TRUE;
    }

  if (dn)
    ldap_dnfree (dn);

  /* Allow user@domain */
  const gchar *at = strchr (bind_dn, '@');
  if (at && at != bind_dn
      && at[1] != '\0' && strchr (at + 1, '@') == NULL)
    return TRUE;

  /* Allow DOMAIN\user */
  const gchar *bs = strchr (bind_dn, '\\');
  if (bs && bs != bind_dn
      && bs[1] != '\0' && strchr (bs + 1, '\\') == NULL)
    return TRUE;

  return FALSE;
}

/**
 * @brief Performs a simple bind to the given LDAP connection.
 *
 * @param ldap      LDAP connection handle.
 * @param bind_dn   Distinguished Name (DN) to bind as.
 * @param password  Password for the bind DN.
 *
 * @return GVM_LDAP_SUCCESS on success, or gvm_ldap_return_t
 *         error code otherwise.
 */
gvm_ldap_return_t
gvm_ldap_bind_simple (LDAP *ldap,
                      const gchar *bind_dn,
                      const gchar *password)
{
  gvm_ldap_return_t ret = GVM_LDAP_SUCCESS;
  struct berval credential;

  if (!ldap || !ldap_bind_dn_is_valid (bind_dn)
      || !password || password[0] == '\0')
    return GVM_LDAP_INVALID_VALUE;

  credential.bv_val = (char *) password;
  credential.bv_len = strlen (password);

  ret = ldap_sasl_bind_s (ldap,
                          bind_dn,
                          LDAP_SASL_SIMPLE,
                          &credential,
                          NULL,
                          NULL,
                          NULL);

  if (ret != LDAP_SUCCESS)
    {
      g_warning ("%s: LDAP simple bind failed: %s.",
                 __func__, ldap_err2string (ret));
      return GVM_LDAP_BIND_ERROR;
    }

  return GVM_LDAP_SUCCESS;
}

/**
 * @brief Validates the LDAP search scope.
 *
 * @param scope The LDAP search scope to validate.
 *
 * @return 0 if the scope is valid, -1 otherwise.
 */
static int
validate_ldap_scope (int scope)
{
  switch (scope)
    {
    case LDAP_SCOPE_BASE:
    case LDAP_SCOPE_ONELEVEL:
    case LDAP_SCOPE_SUBTREE:
      return 0;
    default:
      return -1;
    }
}

/**
 * @brief Creates a new LDAP search parameters structure.
 *
 * @param base_dn          The base DN for the search.
 * @param scope            The search scope.
 * @param filter           The search filter.
 * @param attributes       The attributes to retrieve.
 * @param page_size        The page size for paged searches.
 *                         Use 0 for GVM_LDAP_DEFAULT_PAGE_SIZE.
 * @param size_limit       The size limit for the search. Use 0 for no limit.
 * @param timeout_seconds  The timeout for the search in seconds.
 *                         Use 0 for no timeout.
 *
 * @return A pointer to the newly created gvm_ldap_search_params_t structure
 *         or NULL on failure.
 */
gvm_ldap_search_params_t *
gvm_ldap_search_params_new (const gchar *base_dn, int scope, const gchar *filter,
                            gchar **attributes, guint page_size, guint size_limit,
                            guint timeout_seconds)
{
  gvm_ldap_search_params_t *params;

  if (!base_dn || !filter || filter[0] == '\0')
    return NULL;

  if (validate_ldap_scope (scope) != 0)
    {
      g_warning ("Invalid LDAP search scope: %d", scope);
      return NULL;
    }

  params = g_malloc0 (sizeof (gvm_ldap_search_params_t));
  params->base_dn = g_strdup (base_dn);
  params->scope = scope;
  params->filter = filter && filter[0] != '\0' ? g_strdup (filter) : NULL;
  params->attributes = attributes ? g_strdupv (attributes) : NULL;
  params->page_size = page_size > 0 ? page_size : GVM_LDAP_DEFAULT_PAGE_SIZE;
  params->size_limit = size_limit > 0 ? size_limit : 0;
  params->timeout_seconds = timeout_seconds > 0 ? timeout_seconds : 0;

  return params;
}

/**
 * @brief Frees a previously allocated LDAP search parameters structure.
 *
 * @param params The LDAP search parameters structure to free.
 */
void
gvm_ldap_search_params_free (gvm_ldap_search_params_t *params)
{
  if (!params)
    return;

  g_free (params->base_dn);
  g_free (params->filter);
  g_strfreev (params->attributes);
  g_free (params);
}

/**
 * @brief Performs a paged LDAP search using the specified search parameters.
 *        See RFC 2696 https://datatracker.ietf.org/doc/html/rfc2696
 *        for details on the paged results control.
 *
 * @param ldap           LDAP connection handle.
 * @param search_params  Pointer to the search parameters structure.
 * @param callback       Callback function to handle each search result.
 * @param user_data      User data to pass to the callback function.
 *
 * @return GVM_LDAP_SUCCESS on success, or a gvm_ldap_return_t error
 *         code on failure.
 */
gvm_ldap_return_t
gvm_ldap_search_paged (LDAP *ldap,
                       gvm_ldap_search_params_t *search_params,
                       gvm_ldap_search_callback_t callback,
                       gpointer user_data)
{
  struct timeval timeout = {0, 0};
  struct timeval *timeout_ptr = NULL;
  struct berval cookie = {
    .bv_len = 0,
    .bv_val = NULL
  };
  gvm_ldap_return_t ret = GVM_LDAP_SUCCESS;

  if (!ldap || !search_params || !callback || !search_params->base_dn
      || !search_params->filter || search_params->filter[0] == '\0')
    return GVM_LDAP_INVALID_VALUE;

  if (search_params->timeout_seconds > 0)
    {
      timeout.tv_sec = search_params->timeout_seconds;
      timeout.tv_usec = 0;
      timeout_ptr = &timeout;
    }

  for (;;)
   {
      LDAPControl *page_control = NULL;
      LDAPControl *server_controls[2] = {NULL, NULL};
      LDAPControl **returned_controls = NULL;
      LDAPControl *page_response_control = NULL;
      LDAPMessage *result = NULL;
      struct berval next_cookie = {
        .bv_len = 0,
        .bv_val = NULL
      };
      gboolean stop = FALSE;
      gboolean has_more_pages = FALSE;
      int ldap_ret;

      ldap_ret = ldap_create_page_control (ldap,
                                           search_params->page_size,
                                           &cookie,
                                           1,  /* iscritical */
                                           &page_control);
      if (ldap_ret != LDAP_SUCCESS)
        {
          g_warning ("%s: Failed to create page control: %s.",
                     __func__, ldap_err2string (ldap_ret));
          ret = GVM_LDAP_SEARCH_ERROR;
          break;
        }

      server_controls[0] = page_control;

      ldap_ret = ldap_search_ext_s (ldap,
                                    search_params->base_dn,
                                    search_params->scope,
                                    search_params->filter,
                                    search_params->attributes,
                                    0,     /* attrsonly */
                                    server_controls,
                                    NULL,  /* client controls */
                                    timeout_ptr,
                                    search_params->size_limit,
                                    &result);

      ldap_control_free (page_control);
      page_control = NULL;

      if (ldap_ret != LDAP_SUCCESS)
        {
          g_warning ("%s: LDAP search failed: %s.",
                     __func__, ldap_err2string (ldap_ret));
          ret = GVM_LDAP_SEARCH_ERROR;
          goto page_cleanup;
        }

      LDAPMessage *entry = ldap_first_entry (ldap, result);
      while (entry)
        {
          gvm_ldap_search_callback_return_t cb_ret;

          cb_ret = callback (ldap, entry, user_data);

          if (cb_ret == GVM_LDAP_SEARCH_STOP)
            {
              stop = TRUE;
              break;
            }
          else if (cb_ret == GVM_LDAP_SEARCH_CALLBACK_ERROR)
            {
              g_warning ("%s: Callback reported an error.", __func__);
              ret = GVM_LDAP_CALLBACK_ERROR;
              stop = TRUE;
              break;
            }
          entry = ldap_next_entry (ldap, entry);
        }

      if (stop)
        goto page_cleanup;

      int result_code = LDAP_SUCCESS;
      /* Extract page control information. */
      ldap_ret = ldap_parse_result (ldap,
                                    result,
                                    &result_code,
                                    NULL,
                                    NULL,
                                    NULL,
                                    &returned_controls,
                                    0);

      if (ldap_ret != LDAP_SUCCESS)
        {
          g_warning ("%s: Failed to parse LDAP result: %s.",
                     __func__, ldap_err2string (ldap_ret));
          ret = GVM_LDAP_SEARCH_ERROR;
          goto page_cleanup;
        }

      if (result_code != LDAP_SUCCESS)
        {
          g_warning ("%s: LDAP server returned error code: %d"
                     " while parsing result.",
                     __func__, result_code);
          ret = GVM_LDAP_SEARCH_ERROR;
          goto page_cleanup;
        }

      page_response_control = ldap_control_find (LDAP_CONTROL_PAGEDRESULTS,
                                                 returned_controls,
                                                 NULL);
      if (page_response_control == NULL)
        {
          g_warning ("%s: LDAP server did not return a paged response control.",
                     __func__);
          ret = GVM_LDAP_SEARCH_ERROR;
          goto page_cleanup;
        }

      ldap_ret = ldap_parse_pageresponse_control (ldap,
                                                  page_response_control,
                                                  NULL,
                                                  &next_cookie);

      if (ldap_ret != LDAP_SUCCESS)
        {
          g_warning ("%s: Failed to parse paged response control: %s.",
                     __func__, ldap_err2string (ldap_ret));
          ret = GVM_LDAP_SEARCH_ERROR;
          goto page_cleanup;
        }

      /* Check if there are more pages to fetch. */
      has_more_pages = next_cookie.bv_len > 0;

      if (has_more_pages)
        {
          if (cookie.bv_val)
            ber_memfree (cookie.bv_val);

          cookie = next_cookie;
          next_cookie.bv_val = NULL;
          next_cookie.bv_len = 0;
        }

page_cleanup:
      if (next_cookie.bv_val)
        ber_memfree (next_cookie.bv_val);

      if (returned_controls)
        ldap_controls_free (returned_controls);

      if (result)
        ldap_msgfree (result);

      if (ret != GVM_LDAP_SUCCESS || !has_more_pages)
        break;
   }

  if (cookie.bv_val)
    ber_memfree (cookie.bv_val);

  return ret;
}

/**
 *
 * @brief Closes the specified LDAP connection.
 *
 * @param ldap The LDAP connection to close.
 */
void
gvm_ldap_close (LDAP *ldap)
{
  if (ldap)
    ldap_unbind_ext_s (ldap, NULL, NULL);
}

/**
 * @brief Retrieves the distinguished name (DN) of the specified LDAP entry.
 *
 * @param ldap   The LDAP connection.
 * @param entry  The LDAP entry to retrieve the DN from.
 *
 * @return Newly allocated string containing the DN of the LDAP entry,
 *         or NULL on failure. Free with g_free().
 */
gchar *
gvm_ldap_entry_get_dn (LDAP *ldap, LDAPMessage *entry)
{
  char *dn;
  gchar *result;

  if (!ldap || !entry)
    return NULL;

  dn = ldap_get_dn (ldap, entry);
  if (!dn)
    return NULL;

  result = g_strdup (dn);
  ldap_memfree (dn);

  return result;
}

/**
 * @brief Retrieves the first value of the specified attribute from the LDAP entry.
 *
 * @param ldap       The LDAP connection.
 * @param entry      The LDAP entry to retrieve the attribute value from.
 * @param attribute  The attribute name to retrieve the value for.
 *
 * @return Newly allocated string containing the attribute value or NULL.
 *         Free with g_free().
 */
gchar *
gvm_ldap_entry_get_string (LDAP *ldap, LDAPMessage *entry,
                           const gchar *attribute)
{
  struct berval **values;
  gchar *result = NULL;

  if (!ldap || !entry || !attribute)
    return NULL;

  values = ldap_get_values_len (ldap, entry, attribute);
  if (values == NULL)
    return NULL;

  if (values[0] != NULL)
    result = g_strndup (values[0]->bv_val, values[0]->bv_len);

  ldap_value_free_len (values);

  return result;
}

/**
 * @brief Retrieves all values of the specified attribute from the LDAP entry.
 *
 * @param ldap       The LDAP connection.
 * @param entry      The LDAP entry to retrieve the attribute values from.
 * @param attribute  The attribute name to retrieve values for.
 *
 * @return A GPtrArray containing strings of the attribute values or NULL.
 *         Had to be freed by the caller.
 */
GPtrArray *
gvm_ldap_entry_get_strings (LDAP *ldap, LDAPMessage *entry,
                            const gchar *attribute)
{
  struct berval **values;
  GPtrArray *result;

  if (!ldap || !entry || !attribute)
    return NULL;

  values = ldap_get_values_len (ldap, entry, attribute);
  if (!values)
    return NULL;

  result = g_ptr_array_new_with_free_func (g_free);
  for (int i = 0; values[i] != NULL; i++)
    g_ptr_array_add (result,
                     g_strndup (values[i]->bv_val, values[i]->bv_len));

  ldap_value_free_len (values);

  if (result->len == 0)
    {
      g_ptr_array_free (result, TRUE);
      result = NULL;
    }

  return result;
}