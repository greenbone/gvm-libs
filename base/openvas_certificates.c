/* OpenVAS-Client
 * $Id$
 * Description: Certificate structure holding information about certificates
 * like trust level and a copy of the public key.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2008 Intevation GmbH
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

/*!********************************************
 * This file is basically a copy of           *
 * openvas-libnasl/nasl/nasl_signature.h      *
 * (will in turn be moved to libraries after  *
 * cleanup )                                  *
 * Once openvas-libraries and openvas-libnasl *
 * are cleaned up and a dependency client->lib*
 * is introduced, this local copy is obsolete.*
 *******************************************!*/

/*!
 * TODO on "merge"/dependency introduction: Dissolve non-matching module file 
 * name and functions (...certificate vs ...certificateS).
 */

#include "openvas_certificates.h"

/**
 * Returns pointer to freshly allocated and initialized openvas_certificate.
 * The values are not copied, so they have to exist for the lifetime
 * of this openvas_certificate (but they are freed in openvas_certificate_free).
 * 
 * @param fingerpr ingerprint of certificate.
 * @param owner Certificate owners name.
 * @param istrusted Whether this certificate is trustworthy or not.
 * @param pubkey Full public key.
 * 
 * @return Pointer to a fresh openvas_certificate.
 */
openvas_certificate*
openvas_certificate_new(char* fingerpr, char* owner, gboolean istrusted,
                        char* pubkey)
{
  openvas_certificate* cert = emalloc(sizeof(openvas_certificate));
  cert->fpr = fingerpr;
  cert->ownername = owner;
  cert->trusted = istrusted;
  cert->full_public_key = pubkey;
  return cert;
}

/**
 * Frees the openvas_certificate and all associated data.
 * @param cert Certificate which holds pointers to the data.
 */
void
openvas_certificate_free (openvas_certificate* cert)
{
  if(cert == NULL)
    return;
  if(cert->fpr != NULL)
    efree(& (cert->fpr) );
  if( cert->ownername != NULL)
    efree(& (cert->ownername) );
  if(cert->full_public_key != NULL)
    efree(& (cert->full_public_key) );
  efree(&cert);
}
