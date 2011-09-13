/* openvas-libraries/nasl
 * $Id$
 * Description: Implementation of API for SSH functions used by NASL scripts
 *
 * Authors:
 * Michael Wiegand <michael.wiegand@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation.
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

#ifdef HAVE_LIBSSH
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <libssh/libssh.h>

#include "system.h"             /* for emalloc */
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "plugutils.h"

#include "nasl_ssh.h"

/**
 * @brief Set of defines for libssh API changes.
 */
#ifdef LIBSSH_VERSION_INT
#if LIBSSH_VERSION_INT < SSH_VERSION_INT (0, 5, 0)
#define ssh_string_free string_free
#define ssh_channel_new channel_new
#define ssh_channel_open_session channel_open_session
#define ssh_channel_send_eof channel_send_eof
#define ssh_channel_close channel_close
#define ssh_channel_free channel_free
#define ssh_channel_request_exec channel_request_exec
#define ssh_channel_read channel_read
#endif
#endif

/**
 * @brief Enum for the SSH key types.
 *
 * Duplicated from libssh since it does not expose it.
 */
enum public_key_types_e
{
  TYPE_DSS = 1,
  TYPE_RSA,
  TYPE_RSA1
};

/**
 * @brief Convert a key type to a string.
 *
 * @param[in] type  The type to convert.
 *
 * @returns A string for the keytype or NULL if unknown.
 *
 * Duplicated from libssh since it does not expose it.
 */
const char *
type_to_char (int type)
{
  switch (type)
    {
    case TYPE_DSS:
      return "ssh-dss";
    case TYPE_RSA:
      return "ssh-rsa";
    case TYPE_RSA1:
      return "ssh-rsa1";
    default:
      return NULL;
    }
}

/** @todo Duplicated from openvas-manager. */
/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * @todo Handle symbolic links.
 * @todo Move to libs?
 *
 * @param[in]  name  File name.
 *
 * @return 1 if parameter is directory, 0 if it is not, -1 if it does not
 *         exist or could not be accessed.
 */
static int
check_is_dir (const char *name)
{
  struct stat sb;

  if (stat (name, &sb))
    {
      return -1;
    }
  else
    {
      return (S_ISDIR (sb.st_mode));
    }
}

/** @todo Duplicated from openvas-manager. */
/**
 * @brief Recursively removes files and directories.
 *
 * This function will recursively call itself to delete a path and any
 * contents of this path.
 *
 * @param[in]  pathname  Name of file to be deleted from filesystem.
 *
 * @return 0 if the name was successfully deleted, -1 if an error occurred.
 */
int
file_utils_rmdir_rf (const gchar * pathname)
{
  if (check_is_dir (pathname) == 1)
    {
      GError *error = NULL;
      GDir *directory = g_dir_open (pathname, 0, &error);

      if (directory == NULL)
        {
          if (error)
            {
              g_warning ("g_dir_open(%s) failed - %s\n", pathname,
                         error->message);
              g_error_free (error);
            }
          return -1;
        }
      else
        {
          int ret = 0;
          const gchar *entry = NULL;

          while ((entry = g_dir_read_name (directory)) != NULL && (ret == 0))
            {
              gchar *entry_path = g_build_filename (pathname, entry, NULL);
              ret = file_utils_rmdir_rf (entry_path);
              g_free (entry_path);
              if (ret != 0)
                {
                  g_warning ("Failed to remove %s from %s!", entry, pathname);
                  g_dir_close (directory);
                  return ret;
                }
            }
          g_dir_close (directory);
        }
    }

  return g_remove (pathname);
}

/**
 * @brief Connect to the remote system via SSH and execute a command there.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return    NULL in case of error, else a tree_cell containing the result of
 * the command.
 */
tree_cell *
nasl_ssh_exec (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *commandline;
  char *username;
  char *password;
  char *pubkey;
  char *privkey;
  char *passphrase;
  ssh_session session;
  ssh_channel channel;
  int rc;
  int bytecount = 0;
  GString *cmd_response = NULL;
  tree_cell *retc = NULL;
  const char *hostname;
  int port;
  int type = 0;
  char buffer[4096];
  int nbytes;

  port = get_int_local_var_by_name (lexic, "port", 0);
  username = get_str_local_var_by_name (lexic, "login");
  password = get_str_local_var_by_name (lexic, "password");
  commandline = get_str_local_var_by_name (lexic, "cmd");
  privkey = get_str_local_var_by_name (lexic, "privkey");
  pubkey = get_str_local_var_by_name (lexic, "pubkey");
  passphrase = get_str_local_var_by_name (lexic, "passphrase");

  if ((port <= 0) || (username == NULL) || (commandline == NULL))
    {
      fprintf (stderr,
               "Insufficient parameters: port=%d, username=%s, commandline=%s!\n",
               port, username, commandline);
      return NULL;
    }
  if ((privkey == NULL) && (password == NULL))
    {
      fprintf (stderr,
               "Insufficient parameters: Both privkey and password are NULL!\n");
      return NULL;
    }

  hostname = plug_get_hostname (script_infos);

  session = ssh_new ();

  ssh_options_set (session, SSH_OPTIONS_HOST, hostname);
  ssh_options_set (session, SSH_OPTIONS_USER, username);
  ssh_options_set (session, SSH_OPTIONS_PORT, &port);

  ssh_connect (session);
  if (session == NULL)
    {
      fprintf (stderr, "Failed to establish SSH session!\n");
      ssh_free (session);
      return NULL;
    }

  if (strlen (password) != 0)
    {
      /* We could authenticate via password */
      rc = ssh_userauth_password (session, NULL, password);
      if (rc != SSH_AUTH_SUCCESS)
        {
          fprintf (stderr, "SSH password authentication failed: %s\n",
                   ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
    }
  else
    {
      /* Or by public key */
      ssh_private_key ssh_privkey;
      ssh_string pubkey_string;
      /* This is only needed if we generate the public key from the private key
       * (see below).
       */
#if 0
      ssh_public_key ssh_pubkey;
#endif
      gchar *pubkey_filename;
      gchar *privkey_filename;
      gchar *pubkey_contents;
      const char *privkey_type;
      char key_dir[] = "/tmp/openvas_key_XXXXXX";
      GError *error;

      /* Write the keyfiles to a temporary directory. */
      /**
       * @todo Ultimately we would like to be able to use the keys we already
       * have in memory, unfortunately libssh does not support this yet.
       * In June 2011, libssh developers were confident to introduce this
       * feature for libssh > 0.5 with the new ssh_pki_import_* API.
       * */
      if (mkdtemp (key_dir) == NULL)
        {
          fprintf (stderr, "%s: mkdtemp failed\n", __FUNCTION__);
          ssh_free (session);
          return NULL;
        }

      pubkey_filename = g_strdup_printf ("%s/key.pub", key_dir);
      privkey_filename = g_strdup_printf ("%s/key", key_dir);

      error = NULL;
      g_file_set_contents (privkey_filename, privkey, strlen (privkey), &error);
      if (error)
        {
          fprintf (stderr, "Failed to write private key: %s", error->message);
          g_error_free (error);
          g_free (privkey_filename);
          ssh_disconnect (session);
          ssh_free (session);
          file_utils_rmdir_rf (key_dir);
          return NULL;
        }

      g_chmod (privkey_filename, S_IRUSR | S_IWUSR);

      ssh_privkey =
        privatekey_from_file (session, privkey_filename, TYPE_RSA, passphrase);
      if (ssh_privkey == NULL)
        {
          fprintf (stderr, "Reading private key %s failed (%s)\n",
                   privkey_filename, ssh_get_error (session));
          g_free (privkey_filename);
          ssh_disconnect (session);
          ssh_free (session);
          file_utils_rmdir_rf (key_dir);
          return NULL;
        }

      type = ssh_privatekey_type (ssh_privkey);
      privkey_type = type_to_char (type);
      pubkey_contents =
        g_strdup_printf ("%s %s user@host", privkey_type, pubkey);

      g_file_set_contents (pubkey_filename, pubkey_contents,
                           strlen (pubkey_contents), &error);
      if (error)
        {
          fprintf (stderr, "Failed to write public key: %s", error->message);
          g_error_free (error);
          g_free (pubkey_filename);
          g_free (privkey_filename);
          privatekey_free (ssh_privkey);
          ssh_disconnect (session);
          ssh_free (session);
          file_utils_rmdir_rf (key_dir);
          return NULL;
        }

      g_free (pubkey_contents);

      g_chmod (pubkey_filename, S_IRUSR | S_IWUSR);

      rc =
        ssh_try_publickey_from_file (session, privkey_filename, &pubkey_string,
                                     &type);
      if (rc != 0)
        {
          fprintf (stderr, "ssh_try_publickey_from_file failed: %d\n", rc);
          g_free (pubkey_filename);
          g_free (privkey_filename);
          ssh_disconnect (session);
          ssh_free (session);
          file_utils_rmdir_rf (key_dir);
          return NULL;
        }

      /* The code below would in theory generate the public key from the private
       * key. It is not yet known if this would work for all keys.
       */
#if 0
      if (rc == 1)
        {
          char *publickey_file;
          size_t len;

          ssh_pubkey = publickey_from_privatekey (ssh_privkey);
          if (ssh_pubkey == NULL)
            {
              privatekey_free (ssh_privkey);
              return NULL;
            }

          pubkey_string = publickey_to_string (ssh_pubkey);
          type = ssh_privatekey_type (ssh_privkey);
          publickey_free (ssh_pubkey);
          if (pubkey_string == NULL)
            {
              return NULL;
            }

          len = strlen (privkey_filename) + 5;
          publickey_file = malloc (len);
          if (publickey_file == NULL)
            {
              return NULL;
            }
          snprintf (publickey_file, len, "%s.pub", privkey_filename);
          rc =
            ssh_publickey_to_file (session, publickey_file, pubkey_string,
                                   type);
          if (rc < 0)
            {
              fprintf (stderr, "Could not write public key to file: %s",
                       publickey_file);
            }
        }
      else if (rc < 0)
        {
          /* TODO: Handle Error */
        }
#endif

      rc = ssh_userauth_offer_pubkey (session, NULL, type, pubkey_string);
      if (rc == SSH_AUTH_ERROR)
        {
          fprintf (stderr, "Publickey authentication error");
          ssh_string_free (pubkey_string);
          privatekey_free (ssh_privkey);
          g_free (pubkey_filename);
          g_free (privkey_filename);
          ssh_disconnect (session);
          ssh_free (session);
          file_utils_rmdir_rf (key_dir);
          return NULL;
        }
      else
        {
          if (rc != SSH_AUTH_SUCCESS)
            {
              fprintf (stderr, "Publickey refused by server");
              ssh_string_free (pubkey_string);
              privatekey_free (ssh_privkey);
              g_free (pubkey_filename);
              g_free (privkey_filename);
              ssh_disconnect (session);
              ssh_free (session);
              file_utils_rmdir_rf (key_dir);
              return NULL;
            }
        }

      /* Public key accepted by server! */
      rc = ssh_userauth_pubkey (session, NULL, pubkey_string, ssh_privkey);
      if (rc == SSH_AUTH_ERROR)
        {
          fprintf (stderr, "ssh_userauth_pubkey failed!\n");
          ssh_string_free (pubkey_string);
          privatekey_free (ssh_privkey);
          g_free (pubkey_filename);
          g_free (privkey_filename);
          ssh_disconnect (session);
          ssh_free (session);
          file_utils_rmdir_rf (key_dir);
          return NULL;
        }
      else
        {
          if (rc != SSH_AUTH_SUCCESS)
            {
              fprintf (stderr,
                       "The server accepted the public key but refused the signature");
              ssh_string_free (pubkey_string);
              privatekey_free (ssh_privkey);
              g_free (pubkey_filename);
              g_free (privkey_filename);
              ssh_disconnect (session);
              ssh_free (session);
              file_utils_rmdir_rf (key_dir);
              return NULL;
            }
        }

      /* auth success */
      ssh_string_free (pubkey_string);
      privatekey_free (ssh_privkey);

      g_free (pubkey_filename);
      g_free (privkey_filename);

      file_utils_rmdir_rf (key_dir);
    }

  channel = ssh_channel_new (session);
  if (channel == NULL)
    {
      ssh_disconnect (session);
      ssh_free (session);
      fprintf (stderr, "ssh_channel_new failed!\n");
      return NULL;
    }

  rc = ssh_channel_open_session (channel);
  if (rc < 0)
    {
      fprintf (stderr, "ssh_channel_open_session failed!\n");
      ssh_channel_send_eof (channel);
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      ssh_disconnect (session);
      ssh_free (session);
      return NULL;
    }

  rc = ssh_channel_request_exec (channel, commandline);
  if (rc < 0)
    {
      fprintf (stderr, "ssh_channel_request_exec failed!\n");
      ssh_channel_send_eof (channel);
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      ssh_disconnect (session);
      ssh_free (session);
      return NULL;
    }

  cmd_response = g_string_new ("");
  nbytes = ssh_channel_read (channel, buffer, sizeof (buffer), 0);
  while (nbytes > 0)
    {
      g_string_append_len (cmd_response, buffer, nbytes);
      bytecount += nbytes;
      nbytes = ssh_channel_read (channel, buffer, sizeof (buffer), 0);
    }

  if (nbytes < 0)
    {
      fprintf (stderr, "ssh_channel_read failed!\n");
      ssh_channel_send_eof (channel);
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      ssh_disconnect (session);
      ssh_free (session);
      return NULL;
    }

  ssh_channel_send_eof (channel);
  ssh_channel_close (channel);
  ssh_channel_free (channel);
  ssh_disconnect (session);
  ssh_free (session);

  if (cmd_response != NULL)
    {
      retc = alloc_typed_cell (CONST_DATA);
      retc->size = bytecount;
      retc->x.str_val = g_strdup (cmd_response->str);
      g_string_free (cmd_response, TRUE);
      return retc;
    }
  else
    {
      return NULL;
    }
}
#endif
