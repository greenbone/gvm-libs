/* openvas-libraries/base
 * $Id$
 * Description: Facilities for certificates and certificate collections.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file certificate.c
 * @brief Facilities for certificates and certificate collections.
 *
 * This file provides facilities for data about certificates, and
 * collections of such data.  This includes two types, certificate_t
 * and certificates_t, and functions for manipulating structures of
 * these types.
 */

/**
 * @todo Correct doc or implementation for the set_* methods, they always
 *       return 0.
 */

#include "certificate.h"

/**
 * @brief Create a new, empty certificate structure.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else an empty certificate structure which needs to be
 *         released using @ref certificate_free .
 */
certificate_t *
certificate_create ()
{
  return (certificate_t *) g_malloc0 (sizeof (certificate_t));
}

/**
 * @brief Free memory of a certificate structure.
 *
 * @param  n  The structure to be freed.
 */
void
certificate_free (certificate_t * certificate)
{
  if (certificate == NULL)
    return;
  if (certificate->fingerprint)
    g_free (certificate->fingerprint);
  if (certificate->owner)
    g_free (certificate->owner);
  if (certificate->public_key)
    g_free (certificate->public_key);
  g_free (certificate);
}

/**
 * @brief Get the fingerprint of a certificate.
 *
 * @param  certificate  The certificate.
 *
 * @return The fingerprint, which may be NULL.
 */
const gchar *
certificate_fingerprint (const certificate_t * certificate)
{
  return certificate->fingerprint;
}

/**
 * @brief Get the owner of a certificate.
 *
 * @param  certificate  The certificate.
 *
 * @return The owner, which may be NULL.
 */
const gchar *
certificate_owner (const certificate_t * certificate)
{
  return certificate->owner;
}

/**
 * @brief Get the public key of a certificate.
 *
 * @param  certificate  The certificate.
 *
 * @return The public key, which may be NULL.
 */
const gchar *
certificate_public_key (const certificate_t * certificate)
{
  return certificate->public_key;
}

/**
 * @brief Set the fingerprint of a certificate.
 *
 * @param  certificate  The certificate.
 * @param  fingerprint  The fingerprint.
 *
 * @return 0 on success, -1 on error.
 */
int
certificate_set_fingerprint (certificate_t * certificate,
                             const gchar * fingerprint)
{
  if (certificate->fingerprint)
    g_free (certificate->fingerprint);
  // FIX this aborts on out of mem, while certificate_create returns NULL
  certificate->fingerprint = g_strdup (fingerprint);
  return 0;
}

/**
 * @brief Set the owner of a certificate.
 *
 * @param  certificate  The certificate.
 * @param  owner        The owner.
 *
 * @return 0 on success, -1 on error.
 */
int
certificate_set_owner (certificate_t * certificate, const gchar * owner)
{
  if (certificate->owner)
    g_free (certificate->owner);
  certificate->owner = g_strdup (owner);
  return 0;
}

/**
 * @brief Set the public key of a certificate.
 *
 * @param  certificate  The certificate.
 * @param  public key   The public key.
 *
 * @return 0 on success, -1 on error.
 */
int
certificate_set_public_key (certificate_t * certificate,
                            const gchar * public_key)
{
  if (certificate->public_key)
    g_free (certificate->public_key);
  certificate->public_key = g_strdup (public_key);
  return 0;
}

/**
 * @brief Set the trustedness of a certificate.
 *
 * @param  certificate  The certificate.
 * @param  trusted      TRUE if trusted, else FALSE.
 */
void
certificate_set_trusted (certificate_t * certificate, gboolean trusted)
{
  certificate->trusted = trusted;
}


/* Collections of certificates. */

/**
 * @brief Make a collection of certificates.
 *
 * @return A new collection of certificates or NULL on error.
 */
certificates_t *
certificates_create ()
{
  certificates_t *certs;
  certs = (certificates_t *) g_malloc0 (sizeof (certificates_t));
  return certs;
}

/**
 * @brief Free a collection of certificates.
 *
 * @param  certificates  The collection of certificates.
 */
void
certificates_free (certificates_t * certificates)
{
  GSList *list;
  if (certificates == NULL)
    return;
  for (list = certificates->list; list; list = g_slist_next (list))
    certificate_free (list->data);
  g_slist_free (certificates->list);
  g_free (certificates);
}

/**
 * @brief Add a certificate to a collection of certificate
 *
 * @param  certificates  The collection of certificates.
 */
void
certificates_add (certificates_t * certificates, certificate_t * certificate)
{
  if (certificate)
    certificates->list =
      g_slist_prepend (certificates->list, (gpointer) certificate);
}
