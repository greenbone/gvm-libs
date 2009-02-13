/* OpenVAS-libraries
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

#include <glib/gstdio.h>
#include "includes.h"

#include "openvas_ssh_login.h"

#define KEY_SSHLOGIN_USERNAME     "username"
#define KEY_SSHLOGIN_PUBKEY_FILE  "pubkey_file"
#define KEY_SSHLOGIN_PRIVKEY_FILE "privkey_file"
#define KEY_SSHLOGIN_COMMENT      "comment"
#define KEY_SSHLOGIN_PASSPHRASE   "passphrase"

/**
 * Replacement for g_file_test which is unreliable on windows
 * if nessus and gtk are compiled with a different libc.
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
file_check_exists (const char* name)
{
  struct stat sb;

  if(stat(name, &sb))
    return 0;
  else
    return 1;
}

/**
 * @brief Initializes a openvas_ssh_login.
 * 
 * Key and Info files have to be created separately.
 * 
 * @return A fresh openvas_ssh_login.
 */
openvas_ssh_login* openvas_ssh_login_new(char* name, char* pubkey_file, char* privkey_file,
                                         char* passphrase, char* comment,
                                         char* uname)
{
  openvas_ssh_login* loginfo = emalloc(sizeof(openvas_ssh_login));
  loginfo->name = name;
  loginfo->username = uname;
  loginfo->public_key_path = pubkey_file;
  loginfo->private_key_path = privkey_file;
  loginfo->ssh_key_passphrase = passphrase;
  loginfo->comment = comment;

  return loginfo;
}


/**
 * @brief Frees data associated with a openvas_ssh_login.
 * 
 * @param loginfo openvas_ssh_login to free.
 */
void openvas_ssh_login_free(openvas_ssh_login* loginfo)
{
  if(loginfo == NULL)
    return;
  if(loginfo->name)
    efree(&loginfo->name);
  if(loginfo->username)
    efree(&loginfo->username);
  if(loginfo->public_key_path)
    efree(&loginfo->public_key_path);
  if(loginfo->private_key_path)
    efree(&loginfo->private_key_path);
  if(loginfo->ssh_key_passphrase)
    efree(&loginfo->ssh_key_passphrase);
  if(loginfo->comment)
    efree(&loginfo->comment);
  efree(&loginfo);
}

/**
 * @brief Creates a string to be sent to the server as value for a SSH_LOGIN
 *        plugin preference.
 * 
 * It follows the pattern:
 * username|userpass|pubkeyfilepath|privkeyfilepath|passphrase .
 * 
 * @param loginfo openvas_ssh_login that will be used to assemble the string.
 * 
 * @return Freshly created string or NULL if loginfo == NULL.
 */
char*
openvas_ssh_login_prefstring(openvas_ssh_login* loginfo)
{
  if(loginfo != NULL)
    return g_strjoin("|", loginfo->username, loginfo->public_key_path, 
                     loginfo->private_key_path, loginfo->ssh_key_passphrase,
                     NULL);
  else return NULL;
}

// ---------------- File store functions ------------------

/**
 * @brief Callback for a g_hashtable_for_each. Adds entries to a GKeyFile.
 */
static void add_sshlogin_to_file(char* name, openvas_ssh_login* loginfo, 
                                 GKeyFile* key_file)
{
  if(name == NULL || key_file == NULL || loginfo == NULL)
    return;

  g_key_file_set_string(key_file, loginfo->name, KEY_SSHLOGIN_USERNAME, 
                        loginfo->username);
  g_key_file_set_string(key_file, loginfo->name, KEY_SSHLOGIN_PUBKEY_FILE, 
                        loginfo->public_key_path);
  g_key_file_set_string(key_file, loginfo->name, KEY_SSHLOGIN_PRIVKEY_FILE, 
                        loginfo->private_key_path);
  g_key_file_set_string(key_file, loginfo->name, KEY_SSHLOGIN_COMMENT, 
                        loginfo->comment);
  g_key_file_set_string(key_file, loginfo->name, KEY_SSHLOGIN_PASSPHRASE, 
                        loginfo->ssh_key_passphrase);
}


/**
 * @brief Writes information of all ssh logins found in a hashtable into a file.
 * To load the information again, openvas_ssh_login_file_read can be used.
 * 
 * @param ssh_logins Hashtable with pointers to openvas_ssh_login s as values.
 * @param filename Path to file to wtite to.
 * 
 * @return TRUE if file was written (success), FALSE if an error occured.
 */
gboolean openvas_ssh_login_file_write (GHashTable* ssh_logins, char* filename)
{
  GKeyFile* key_file = g_key_file_new();
  gchar* keyfile_data;
  gsize data_length;
  GError* err = NULL;
  int fd;
  
  g_key_file_set_comment(key_file, NULL, NULL, 
                         "This file was generated by OpenVAS and shall not be edited manually.",
                         &err);
  if (err != NULL)
  {
    //show_error(_("Error adding comment to key file: %s"), err->message);
    g_error_free(err);
    g_key_file_free(key_file);
    return FALSE;
  }

  // Add all ssh logins to GKeyFile.
  if(ssh_logins != NULL)
  {
    g_hash_table_foreach(ssh_logins, (GHFunc) add_sshlogin_to_file, key_file);    
  } // (else file content is comment only)
  
  // Write GKeyFile to filesystem.
  fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0600);
  if(!fd)
  {
    //show_error(_("Error accessing ssh info file."));
    g_key_file_free(key_file);
    return FALSE;
  }

  keyfile_data = g_key_file_to_data(key_file, &data_length, &err);
  if(err != NULL)
  {
    //show_error(_("Error exporting ssh info file: %s"), err->message);
    close(fd);
    g_error_free(err);
    g_key_file_free(key_file);
    return FALSE;
  }

  write(fd, keyfile_data, data_length);
  close(fd);

  g_key_file_free(key_file);

  return TRUE;
}

/**
 * @brief Reads a ssh_login file and returns info in a GHashTable.
 * 
 * The GHashTable contains the names as keys and pointers to openvas_ssh_logins
 * as values.
 * If check_keyfiles TRUE, openvas_ssh_logins are checked before being 
 * added to the hashtable:
 * if the public and private key files do not exist, the openvas_ssh_login would
 * not be added.
 * 
 * @param filename       File to read from.
 * @param check_keyfiles If TRUE, checks if referenced keyfiles do exist, before
 *                       adding the openvas_ssh_login to the HashTable.
 * 
 * @return GHashTable, keys are names of openvas_ssh_logins, who are values.
 */
GHashTable*
openvas_ssh_login_file_read (char* filename, gboolean check_keyfiles)
{
  gchar** names;
  gsize length;
  GKeyFile* key_file = g_key_file_new();
  GError* err        = NULL;
  GHashTable* loginfos   = g_hash_table_new_full(g_str_hash, g_str_equal, 
      NULL, (GDestroyNotify) openvas_ssh_login_free);

  g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, &err);

  if(err != NULL)
  {
    // No file found? Thats ok, return empty hashtable.
    if(err->code == G_KEY_FILE_ERROR_NOT_FOUND || err->code == G_FILE_ERROR_NOENT)
    {
      g_key_file_free(key_file);
      return loginfos;
    }
      
    g_hash_table_destroy(loginfos);
    //show_error(_("Error loading sshlogin store %s: %s"), filename,
    //           err->message);
    g_key_file_free(key_file);
    return NULL;
  }

  names = g_key_file_get_groups(key_file, &length);

  // Read ssh login information from file and add entry to hashtable.
  int i = 0;
  for(i = 0; i < length; i++)
  {
    if(names[i] == NULL || names[i] == '\0')
      continue;
    // Init a openvas_ssh_login
    char* name = names[i];
    char* username = g_key_file_get_string(key_file, names[i], 
                                           KEY_SSHLOGIN_USERNAME, &err);
    char* pubkey   = g_key_file_get_string(key_file, names[i], 
                                           KEY_SSHLOGIN_PUBKEY_FILE, &err);
    char* privkey  = g_key_file_get_string(key_file, names[i], 
                                           KEY_SSHLOGIN_PRIVKEY_FILE, &err);
    char* comment  = g_key_file_get_string(key_file, names[i], 
                                           KEY_SSHLOGIN_COMMENT, &err);
    char* passphrase = g_key_file_get_string(key_file, names[i], 
                                             KEY_SSHLOGIN_PASSPHRASE, &err);
    
    openvas_ssh_login* loginfo = openvas_ssh_login_new(name, pubkey, privkey,
                                  passphrase, comment, username);

    // Discard if error or files do not exist (depending on check_keyfiles param)
    if (err != NULL)
    {
      openvas_ssh_login_free(loginfo);
    }
    else if (check_keyfiles == TRUE 
             && (file_check_exists(pubkey) == 0 || file_check_exists(privkey) == 0) )
    {
      openvas_ssh_login_free(loginfo);
    }
    else
    {
      // Add to hash table otherwise
      g_hash_table_insert(loginfos, loginfo->name, loginfo);
    }
  }

  g_key_file_free(key_file);

  return loginfos;
}
