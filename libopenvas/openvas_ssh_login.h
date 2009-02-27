/* OpenVAS-Client
 * $Id$
 * Description: SSH Key management.
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
 *
 * In addition, as a special exception, you have
 * permission to link the code of this program with the OpenSSL
 * library (or with modified versions of OpenSSL that use the same
 * license as OpenSSL), and distribute linked combinations including
 * the two. You must obey the GNU General Public License in all
 * respects for all of the code used other than OpenSSL. If you
 * modify this file, you may extend this exception to your version
 * of the file, but you are not obligated to do so. If you do not
 * wish to do so, delete this exception statement from your version.
 */
 
#ifndef _OPENVAS_SSH_LOGIN_H
#define _OPENVAS_SSH_LOGIN_H

#include <glib.h>

/**
 * SSH Login information struct.
 */
typedef struct {
  char* name;
  char* username;
  char* userpassword;
  char* public_key_path;
  char* private_key_path;
  char* ssh_key_passphrase;
  char* comment;
  gboolean valid; /**< TRUE if all information and files available, FALSE otherwise.*/
} openvas_ssh_login;

openvas_ssh_login* openvas_ssh_login_new(char* name, char* pubkey_file,
                                         char* privkey_file, char* passphrase,
                                         char* comment, char* uname, char* upass);

void openvas_ssh_login_free(openvas_ssh_login* loginfo);

GHashTable* openvas_ssh_login_file_read(char* filename, gboolean);

gboolean openvas_ssh_login_file_write(GHashTable* ssh_logins, char* filename);

char* openvas_ssh_login_prefstring(openvas_ssh_login* loginfo);

#endif
