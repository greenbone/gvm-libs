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

#ifndef _OPENVAS_CERTIFICATES_H
#define _OPENVAS_CERTIFICATES_H

#include <includes.h>

#include <glib.h>

typedef struct {
  char* fpr;
  char* ownername;
  gboolean trusted;
  char* full_public_key;
} openvas_certificate;

openvas_certificate* openvas_certificate_new(char*, char*, gboolean, 
                                                    char*);
void openvas_certificate_free(openvas_certificate*);

#endif
