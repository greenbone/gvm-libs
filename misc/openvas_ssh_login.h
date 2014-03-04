/* OpenVAS Libraries
 * $Id$
 * Description: LSC Credentials management.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
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

#ifndef _OPENVAS_SSH_LOGIN_H
#define _OPENVAS_SSH_LOGIN_H

#include <glib.h>

/**
 * SSH Login information struct. (credentials)
 */
typedef struct
{
  char *name;                   /// Name to identify this credentials
  char *username;               /// Name of the user
  char *userpassword;           /// Password of the user
  char *public_key_path;        /// Path to the public key
  char *private_key_path;       /// Path to the private key
  char *ssh_key_passphrase;     /// Passphrase for the key
  char *comment;                /// Optional comment
  gboolean valid;           /**< @brief TRUE if all information and key files
                             *         available, FALSE otherwise.*/
} openvas_ssh_login;

openvas_ssh_login *openvas_ssh_login_new (char *name, char *pubkey_file,
                                          char *privkey_file, char *passphrase,
                                          char *comment, char *uname,
                                          char *upass);

void openvas_ssh_login_free (openvas_ssh_login * loginfo);

GHashTable *openvas_ssh_login_file_read_buffer (const char *buffer,
                                                gsize buffer_size,
                                                gboolean check);

#endif
