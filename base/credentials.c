/* SPDX-FileCopyrightText: 2010-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Credential pairs and triples.
 */

#include "credentials.h"

#include "strings.h" /* for gvm_append_text */

#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/**
 * @brief Free credentials.
 *
 * Free the members of a credentials pair.
 *
 * @param[in]  credentials  Pointer to the credentials.
 */
void
free_credentials (credentials_t *credentials)
{
  g_free (credentials->username);
  g_free (credentials->password);
  g_free (credentials->uuid);
  g_free (credentials->timezone);
  g_free (credentials->role);
  g_free (credentials->severity_class);
  memset (credentials, '\0', sizeof (*credentials));
}

/**
 * @brief Append text to the username of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void
append_to_credentials_username (credentials_t *credentials, const char *text,
                                gsize length)
{
  gvm_append_text (&credentials->username, text, length);
}

/**
 * @brief Append text to the password of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void
append_to_credentials_password (credentials_t *credentials, const char *text,
                                gsize length)
{
  gvm_append_text (&credentials->password, text, length);
}
