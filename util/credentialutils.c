/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Functions for handling scan credentials.
 */

#include "credentialutils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

/**
 * @brief Struct credential information.
 */
struct scan_credential
{
  gchar *type;           /**< Credential type */
  gchar *service;        /**< Service the credential is for */
  gchar *port;           /**< Port the credential is for */
  GHashTable *auth_data; /**< Authentication data (username, password, etc.)*/
};

/**
 * @brief Allocate and initialize a new scan credential.
 *
 * @param[in]   type      The credential type.
 * @param[in]   service   The service the credential is for.
 * @param[in]   port      The port.
 *
 * @return New osp credential.
 */
scan_credential_t *
scan_credential_new (const char *type, const char *service, const char *port)
{
  scan_credential_t *new_credential;

  new_credential = g_malloc0 (sizeof (scan_credential_t));

  new_credential->type = type ? g_strdup (type) : NULL;
  new_credential->service = service ? g_strdup (service) : NULL;
  new_credential->port = port ? g_strdup (port) : NULL;
  new_credential->auth_data =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  return new_credential;
}

/**
 * @brief Get the type of a scan credential.
 *
 * @param[in]  credential  The credential to get the type from.
 *
 * @return The type of the credential or NULL if not available.
 */
const gchar *
scan_credential_get_type (scan_credential_t *credential)
{
  if (!credential)
    return NULL;
  return credential->type;
}

/**
 * @brief Get the service of a scan credential.
 *
 * @param[in]  credential  The credential to get the service from.
 *
 * @return The service of the credential or NULL if not available.
 */
const gchar *
scan_credential_get_service (scan_credential_t *credential)
{
  if (!credential)
    return NULL;
  return credential->service;
}

/**
 * @brief Get the port of a scan credential.
 *
 * @param[in]  credential  The credential to get the port from.
 *
 * @return The port of the credential or NULL if not available.
 */
const gchar *
scan_credential_get_port (scan_credential_t *credential)
{
  if (!credential)
    return NULL;
  return credential->port;
}

/**
 * @brief Iterate over each authentication data item in a scan credential.
 *
 * @param[in]  credential  The credential to iterate over.
 * @param[in]  func        The function to call for each
 *                          authentication data item.
 * @param[in]  user_data   User data to pass to the function.
 */
void
scan_credential_foreach_auth_data (scan_credential_t *credential,
                                   void (*func) (const char *name,
                                                 const char *value,
                                                 void *user_data),
                                   void *user_data)
{
  if (!credential || !func)
    return;

  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init (&iter, credential->auth_data);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      func ((const char *) key, (const char *) value, user_data);
    }
}

/**
 * @brief Free a scan credential.
 *
 * @param[in]   credential  The credential to free.
 */
void
scan_credential_free (scan_credential_t *credential)
{
  if (!credential)
    return;

  g_free (credential->type);
  g_free (credential->service);
  g_free (credential->port);
  g_hash_table_destroy (credential->auth_data);
  g_free (credential);
}

/**
 * @brief Get authentication data from a scan credential.
 *
 * @param[in]  credential  The credential to get the data from.
 * @param[in]  name        The name of the data item to get.
 *
 * @return The requested authentication data or NULL if not available.
 */
const gchar *
scan_credential_get_auth_data (scan_credential_t *credential, const char *name)
{
  if (credential == NULL || name == NULL)
    return NULL;
  return g_hash_table_lookup (credential->auth_data, name);
}

/**
 * @brief Set authentication data for a scan credential.
 *
 * @param[in]  credential  The credential to set the data for.
 * @param[in]  name        The name of the data item to set.
 * @param[in]  value       The authentication data or NULL to unset.
 */
void
scan_credential_set_auth_data (scan_credential_t *credential, const char *name,
                               const char *value)
{
  if (credential == NULL || name == NULL)
    return;

  if (g_regex_match_simple ("^[[:alpha:]][[:alnum:]_]*$", name, 0, 0))
    {
      if (value)
        g_hash_table_replace (credential->auth_data, g_strdup (name),
                              g_strdup (value));
      else
        g_hash_table_remove (credential->auth_data, name);
    }
  else
    {
      g_warning ("%s: Invalid auth data name: %s", __func__, name);
    }
}
