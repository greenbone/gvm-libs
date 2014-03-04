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

#include <glib/gstdio.h>

#include <fcntl.h>              /* for open */
#include <unistd.h>             /* for write */

#include "openvas_ssh_login.h"

#define KEY_SSHLOGIN_USERNAME     "username"
#define KEY_SSHLOGIN_USERPASSWORD "userpassword"
#define KEY_SSHLOGIN_PUBKEY_FILE  "pubkey_file"
#define KEY_SSHLOGIN_PRIVKEY_FILE "privkey_file"
#define KEY_SSHLOGIN_COMMENT      "comment"
#define KEY_SSHLOGIN_PASSPHRASE   "passphrase"

/**
 * @TODO This module fulfils the reqirements to be placed in the base library.
 */

/**
 * Replacement for g_file_test which is unreliable on windows
 * if OpenVAS and GTK are compiled with a different libc.
 * TODO: The windows issue needs verification and proper documentation. Maybe a
 * proper build could prohibit any problems.
 *
 *
 * FIXME: handle symbolic links
 * FIXME: this one is a code duplicate of check_exists in
 * openvas-client/context.c, but needed in openvas-libraries as well.
 *
 * @return 1 if file exists, 0 otherwise.
 */
int
file_check_exists (const char *name)
{
  struct stat sb;

  if (stat (name, &sb))
    return 0;
  else
    return 1;
}

/**
 * @brief Initializes a openvas_ssh_login.
 *
 * Key and Info files have to be created separately.
 * However, it is tested if the keyfiles do exist and the 'valid' flag is set
 * accordingly.
 * Note that the parameter are not copied, so ensure they live as long as this
 * login.
 *
 * @return A fresh openvas_ssh_login.
 */
openvas_ssh_login *
openvas_ssh_login_new (char *name, char *pubkey_file, char *privkey_file,
                       char *passphrase, char *comment, char *uname,
                       char *upass)
{
  openvas_ssh_login *loginfo = g_malloc0 (sizeof (openvas_ssh_login));
  loginfo->name = name;
  loginfo->username = uname;
  loginfo->userpassword = upass;
  loginfo->public_key_path = pubkey_file;
  loginfo->private_key_path = privkey_file;
  loginfo->ssh_key_passphrase = passphrase;
  loginfo->comment = comment;

  loginfo->valid = (file_check_exists (pubkey_file) == 1
                    && file_check_exists (privkey_file) == 1);

  return loginfo;
}


/**
 * @brief Frees data associated with a openvas_ssh_login.
 *
 * @param loginfo openvas_ssh_login to free.
 */
void
openvas_ssh_login_free (openvas_ssh_login * loginfo)
{
  if (loginfo == NULL)
    return;
  if (loginfo->name)
    g_free (loginfo->name);
  if (loginfo->username)
    g_free (loginfo->username);
  if (loginfo->userpassword)
    g_free (loginfo->userpassword);
  if (loginfo->public_key_path)
    g_free (loginfo->public_key_path);
  if (loginfo->private_key_path)
    g_free (loginfo->private_key_path);
  if (loginfo->ssh_key_passphrase)
    g_free (loginfo->ssh_key_passphrase);
  if (loginfo->comment)
    g_free (loginfo->comment);
  g_free (loginfo);
}

// ---------------- File store functions ------------------

/**
 * @brief Reads a ssh_login file and returns info in a GHashTable.
 *
 * The GHashTable contains the names as keys and pointers to openvas_ssh_logins
 * as values.
 * If check_keyfiles TRUE, openvas_ssh_logins are checked before being
 * added to the hashtable:
 * if the public and private key files do not exist, the openvas_ssh_login
 * will not be added.
 *
 * @param key_file       Pointer to GKeyFile structure to read from.
 * @param check_keyfiles If TRUE, checks if referenced keyfiles do exist, before
 *                       adding the openvas_ssh_login to the HashTable.
 *
 * @return GHashTable, keys are names of openvas_ssh_logins, who are values.
 */
static GHashTable *
read_from_keyfile (GKeyFile * key_file, gboolean check_keyfiles)
{
  GHashTable *loginfos = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
                                                (GDestroyNotify)
                                                openvas_ssh_login_free);
  gsize length;
  gchar **names = g_key_file_get_groups (key_file, &length);
  GError *err = NULL;

  // Read ssh login information from file and add entry to hashtable.
  int i = 0;
  for (i = 0; i < length; i++)
    {
      if (names[i] == NULL || names[i] == '\0')
        continue;
      // Init a openvas_ssh_login
      char *name = names[i];
      char *username = g_key_file_get_string (key_file, names[i],
                                              KEY_SSHLOGIN_USERNAME, &err);
      char *userpass = NULL;
      char *pubkey = NULL;
      char *privkey = NULL;
      char *comment = NULL;
      char *passphrase = NULL;

      if (err == NULL)
        {
          userpass =
            g_key_file_get_string (key_file, names[i],
                                   KEY_SSHLOGIN_USERPASSWORD, &err);
          // For Compatibility, ignore if key for password is not present
          if (err != NULL)
            {
              userpass = "";
              g_error_free (err);
              err = NULL;
            }
        }

      if (err == NULL)
        pubkey =
          g_key_file_get_string (key_file, names[i], KEY_SSHLOGIN_PUBKEY_FILE,
                                 &err);
      if (err == NULL)
        privkey =
          g_key_file_get_string (key_file, names[i], KEY_SSHLOGIN_PRIVKEY_FILE,
                                 &err);
      if (err == NULL)
        comment =
          g_key_file_get_string (key_file, names[i], KEY_SSHLOGIN_COMMENT,
                                 &err);
      if (err == NULL)
        passphrase =
          g_key_file_get_string (key_file, names[i], KEY_SSHLOGIN_PASSPHRASE,
                                 &err);

      openvas_ssh_login *loginfo = openvas_ssh_login_new (name,
                                                          pubkey, privkey,
                                                          passphrase, comment,
                                                          username, userpass);

      // Discard if error or files do not exist (depending on check_keyfiles param)
      if (err != NULL)
        {
          g_error_free (err);
          openvas_ssh_login_free (loginfo);
        }
      else
        {
          if (check_keyfiles == TRUE && loginfo->valid == FALSE)
            {
              openvas_ssh_login_free (loginfo);
            }
          else
            {
              // Add to hash table otherwise
              g_hash_table_insert (loginfos, loginfo->name, loginfo);
            }
        }
    }

  return loginfos;
}

/**
 * @brief Reads from contents of a ssh_login file and returns info in a
 * @brief GHashTable.
 *
 * Like \ref openvas_ssh_login_file_read, but used when the file content is
 * known already.
 *
 * @param filename       Buffer to read from.
 * @param check_keyfiles If TRUE, checks if referenced keyfiles do exist, before
 *                       adding the openvas_ssh_login to the HashTable.
 *
 * @return GHashTable, keys are names of openvas_ssh_logins, who are values.
 * @see openvas_ssh_login_file_read
 */
GHashTable *
openvas_ssh_login_file_read_buffer (const char *buffer, gsize buffer_size,
                                    gboolean check_keyfiles)
{
  GKeyFile *key_file = g_key_file_new ();
  GError *err = NULL;
  GHashTable *loginfos = NULL;

  g_key_file_load_from_data (key_file, buffer, buffer_size, G_KEY_FILE_NONE,
                             &err);

  if (err != NULL)
    {
      // No file found? Thats ok, return empty hashtable.
      if (err->code == G_KEY_FILE_ERROR_NOT_FOUND
          || err->code == G_FILE_ERROR_NOENT)
        {
          g_key_file_free (key_file);
          g_error_free (err);
          return loginfos;
        }

      //show_error(_("Error loading sshlogin store %s: %s"), filename,
      //           err->message);
      g_key_file_free (key_file);
      g_error_free (err);
      return NULL;
    }

  loginfos = read_from_keyfile (key_file, check_keyfiles);

  g_key_file_free (key_file);

  return loginfos;
}
