/* openvas-libraries/libopenvascommon
 * $Id$
 * Description: Certificate header file.
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
 * @file certificate.h
 * @brief Certificate header file.
 */

#ifndef _CERTIFICATE_H
#define _CERTIFICATE_H

#include <glib.h>

/**
 * @brief Information about a certificate.
 *
 * The elements of this structure should always be accessed using the
 * function interface (get_fingerprint, set_owner, etc.).
 */
typedef struct {
  char* fingerprint;  // Fingerprint.
  char* owner;        // Name of the owner of the certificate.
  char* public_key;   // Full public key.
  gboolean trusted;   // True if the certificate is trusted.
} certificate_t;

certificate_t *certificate_create (void);
void certificate_free (certificate_t *);

const gchar *certificate_fingerprint (const certificate_t *);
const gchar *certificate_owner (const certificate_t *);
const gchar *certificate_public_key (const certificate_t *);
gboolean certificate_trusted (const certificate_t *);

const gchar *certificate_trust_level (const certificate_t *);

int certificate_set_fingerprint (certificate_t *, const gchar *);
int certificate_set_owner (certificate_t *, const gchar *);
int certificate_set_public_key (certificate_t *, const gchar *);
void certificate_set_trusted (certificate_t *, gboolean);


/* Collections of certificates. */

/**
 * @brief A collection of certificates.
 *
 * The elements of this structure should always be accessed using the
 * function interface (certificates_add, etc.).
 */
typedef struct {
  GSList *list;  // A list of pointers to certificate_t's.
} certificates_t;

certificates_t *certificates_create ();
void certificates_free (certificates_t *);

guint certificates_size (certificates_t *);

void certificates_add (certificates_t *, certificate_t *);

certificate_t*
certificates_find (certificates_t* certificates,
                   gconstpointer data,
                   GCompareFunc function);

#endif /* not _CERTIFICATE_H */
