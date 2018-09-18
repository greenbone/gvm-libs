/* openvas-libraries/nasl
 * $Id$
 * Description: Implementation of API for SSH functions used by NASL scripts
 *
 * Authors:
 * Michael Wiegand <michael.wiegand@greenbone.net>
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Copyright (C) 2011, 2012 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * @file nasl_ssh.c
 *
 * @brief Implementation of an API for SSH functions.
 *
 * This file contains the implementaion of the Secure Shell related
 * NASL builtin functions.  They are only available if build with
 * libssh support.
 */

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

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "../misc/plugutils.h"
#include "../base/kb.h"
#include "nasl_debug.h"
#include "../misc/network.h"            /* for openvas_get_socket_from_connection */
#include "../misc/openvas_logging.h"
#include "../misc/prefs.h"  /* for prefs_get() */
#include "../misc/openvas_ssh.h"

#include "nasl_ssh.h"


#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
# define DIMof(type,member)   DIM(((type *)0)->member)
#endif


#if SSH_OK != 0
# error Oops, libssh ABI changed
#endif


/* This object is used to keep track of libssh contexts.  Because they
   are pointers they can't be mapped easily to the NASL type system.
   We would need to define a new type featuring a callback which would
   be called when that variable will be freed.  This is not easy and
   has several implications.  A clean solution requires a decent
   garbage collector system with an interface to flange arbitrary C
   subsystems to it.  After all we would end up with a complete VM
   and FFI.  We don't want to do that now.

   Our solution is to track those contexts here and clean up any left
   over context at the end of a script run.  We could use undocumented
   "on_exit" feature but that one is not well implemented; thus we use
   explicit code in the interpreter for the cleanup.  The scripts are
   expected to close the sessions, but as long as they don't open too
   many of them, the system will take care of it at script termination
   time.

   We associate each context with a session id, which is a global
   counter of this process.  The simpler version of using slot numbers
   won't allow for better consistency checks.  A session id of 0 marks
   an unused table entry.

   Note that we can't reuse a session for another connection. To use a
   session is always an active or meanwhile broken connection to the
   server.
 */
struct session_table_item_s
{
  int session_id;
  ssh_session session;
  ssh_channel channel;
  int sock;                         /* The associated socket. */
  int authmethods;                  /* Bit fields with available
                                       authentication methods.  */
  unsigned int authmethods_valid:1; /* Indicating that methods is valid.  */
  unsigned int user_set:1;          /* Set if a user has been set for
                                       the session.  */
  unsigned int verbose:1;           /* Verbose diagnostics.  */
};


#define MAX_SSH_SESSIONS 10
static struct session_table_item_s session_table[MAX_SSH_SESSIONS];


/* Local prototypes.  */
static int nasl_ssh_close_hook (int);

static void
g_string_comma_str (GString *gstr, const char *str)
{
  if (gstr->len)
    g_string_append (gstr, ",");
  g_string_append (gstr, str);
}

/* Wrapper functions to make a future migration to the libssh 0.6 API
   easier.  The idea is that you only need to remove these wrappers
   and s/my_ssh_/ssh_/ on this file.  */

#if LIBSSH_VERSION_INT < SSH_VERSION_INT (0, 6, 0)
struct my_ssh_key_s
{
  ssh_private_key privkey;
  int type;
  ssh_string pubkey_string;
};
typedef struct my_ssh_key_s *my_ssh_key;

/* Release an ssh key object.  NULL for KEY is allowed.  */
static void
my_ssh_key_free (my_ssh_key key)
{
  if (!key)
    return;
  privatekey_free (key->privkey);
  ssh_string_free (key->pubkey_string);
  g_free (key);
}

/* Remove the temporary directory and its key file.  FILENAME is also freed. */
static void
remove_and_free_temp_key_file (char *filename)
{
  char *p;

  if (g_remove (filename) && errno != ENOENT)
    log_legacy_write ("Failed to remove temporary file '%s': %s\n",
                      filename, strerror (errno));
  p = strrchr (filename, '/');
  g_assert (p);
  *p = 0;
  if (g_rmdir (filename))
    log_legacy_write ("Failed to remove temporary directory '%s': %s\n",
                      filename, strerror (errno));
  g_free (filename);
}


/* Import a base64 formatted key from a memory c-string.
 *
 * B64_KEY is a string holding the base64 encoded key.  PASSPHRASE is
 * the passphrase used to unprotect that key; if the key has no
 * protection NULL may be passed.  AUTH_FN and AUTH_DATA are defined
 * by libssh to allow for an authentication callback (i.e. asking for
 * the passphrase; it is not used here.  The SESSION is required only
 * for this wrapper.
 *
 * On success the a key object is allocated and stored at PKEY.  The
 * caller must free that value.  It is suggested that the caller
 * stores NULL at it before calling the function.
 *
 * The function returns 0 on success or a non-zero value on failure.
 */
static int
my_ssh_pki_import_privkey_base64(ssh_session session,
                                 int verbose,
                                 const char *b64_key,
                                 const char *passphrase,
                                 void *auth_fn,
                                 void *auth_data,
                                 my_ssh_key *r_pkey)
{
  ssh_private_key ssh_privkey;
  ssh_public_key ssh_pubkey;
  gchar *privkey_filename;
  char key_dir[] = "/tmp/openvas_key_XXXXXX";
  GError *error;
  my_ssh_key pkey;
  char *pkcs8_buffer = NULL;

  /* Write the private key to a file in a temporary directory.  */
  if (!g_mkdtemp_full (key_dir, S_IRUSR|S_IWUSR|S_IXUSR))
    {
      log_legacy_write ("%s: g_mkdtemp_full/mkdtemp failed\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }

  privkey_filename = g_strdup_printf ("%s/key", key_dir);

 read_again:
  error = NULL;
  g_file_set_contents (privkey_filename, b64_key, strlen (b64_key), &error);
  if (error)
    {
      log_legacy_write ("Failed to write private key to temporary file: %s\n",
                        error->message);
      g_error_free (error);
      remove_and_free_temp_key_file (privkey_filename);
      g_free (pkcs8_buffer);
      return SSH_AUTH_ERROR;
    }

  /* We should have created the file with approriate permission in the
     first place.  Unfortunately glib does not allow that.  */
  g_chmod (privkey_filename, S_IRUSR | S_IWUSR);

  ssh_privkey = privatekey_from_file (session, privkey_filename, 0, passphrase);
  if (!ssh_privkey && verbose)
    log_legacy_write ("Reading private key from '%s' failed: %s\n",
                      privkey_filename, ssh_get_error (session));
  if (!ssh_privkey && !pkcs8_buffer)
    {
      if (verbose)
        log_legacy_write ("Converting from PKCS#8 and trying again ...\n");

      pkcs8_buffer = openvas_ssh_pkcs8_decrypt (b64_key, passphrase);
      if (pkcs8_buffer)
        {
          b64_key = pkcs8_buffer;
          g_remove (privkey_filename);
          goto read_again;
        }
    }
  if (pkcs8_buffer)
    {
      g_free (pkcs8_buffer);
      pkcs8_buffer = NULL;
      if (verbose)
        log_legacy_write ("... this worked.\n");
    }

  remove_and_free_temp_key_file (privkey_filename);
  privkey_filename = NULL;
  if (!ssh_privkey)
    return SSH_AUTH_ERROR;

  /* Create our key object.  */
  pkey = g_try_malloc0 (sizeof *pkey);
  if (!pkey)
    {
      privatekey_free (ssh_privkey);
      log_legacy_write ("%s: malloc failed\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }
  pkey->privkey = ssh_privkey;
  pkey->type = ssh_privatekey_type (ssh_privkey);
  if (pkey->type == SSH_KEYTYPE_UNKNOWN)
    {
      my_ssh_key_free (pkey);
      if (verbose)
        log_legacy_write ("%s: key type is not known\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }

  /* Extract the public key from the private key.  */
  ssh_pubkey = publickey_from_privatekey (ssh_privkey);
  if (!ssh_pubkey)
    {
      my_ssh_key_free (pkey);
      if (verbose)
        log_legacy_write ("%s: publickey_from_privatekey failed\n",
                 __FUNCTION__);
      return SSH_AUTH_ERROR;
    }
  pkey->pubkey_string = publickey_to_string (ssh_pubkey);
  publickey_free (ssh_pubkey);
  if (!pkey->pubkey_string)
    {
      my_ssh_key_free (pkey);
      if (verbose)
        log_legacy_write ("%s: publickey_to_string failed\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }

  *r_pkey = pkey;
  return SSH_AUTH_SUCCESS;
}


/* Try to authenticate with the given public key.

   To avoid unnecessary processing and user interaction, the following
   method is provided for querying whether authentication using the
   given key would be possible.

   SESSION is the session object.  USERNAME should be passed as NULL.
   It is expected that ssh_options_set has been been used to set the
   username before the first authentication attempt.  The reason is
   that most servers do not permit changing the username during the
   authentication phase.  KEY is the ssh key object; the function uses
   only the public key part.

   Returns:

    SSH_SUCCESS (0)  - The public key is accepted.

    SSH_AUTH_DENIED  - The server doesn't accept that public key as an
                       authentication token.

    SSH_AUTH_ERROR   - A serious error happened.

    SSH_AUTH_PARTIAL - You have been partially authenticated, you
                       still have to use another method.

 */
static int
my_ssh_userauth_try_publickey (ssh_session session,
                               const char *username,
                               const my_ssh_key key)
{
  int rc;

  (void)username;

  rc = ssh_userauth_offer_pubkey (session, NULL, key->type, key->pubkey_string);
  return rc;
}


/* Authenticate with the given private key.

   SESSION is the session object.  USERNAME should be passed as NULL.
   It is expected that ssh_options_set has been been used to set the
   username before the first authentication attempt.  The reason is
   that most servers do not permit changing the username during the
   authentication phase.  KEY is the ssh key object.

   Returns:

    SSH_SUCCESS (0)  - The public key is accepted.

    SSH_AUTH_DENIED  - The server doesn't accept that key as an
                       authentication token.

    SSH_AUTH_ERROR   - A serious error happened.

    SSH_AUTH_PARTIAL - You have been partially authenticated, you
                       still have to use another method.

 */
static int
my_ssh_userauth_publickey(ssh_session session,
                          const char *username,
                          const my_ssh_key key)
{
  int rc;

  (void)username;

  rc = ssh_userauth_pubkey (session, NULL, key->pubkey_string, key->privkey);
  return rc;
}
#endif



/* Return the next session id.  Note that the first session ID we will
   hand out is an arbitrary high number, this is only to help
   debugging.  This function is also used to setup a hook to the
   network layer. */
static int
next_session_id (void)
{
  static int initialized;
  static int last = 9000;
  int i;

  if (!initialized)
    {
      add_close_stream_connection_hook (nasl_ssh_close_hook);
      initialized = 1;
    }


 again:
  last++;
  /* Because we don't have an unsigned type, it is better to avoid
     negative values.  Thus if LAST turns negative we wrap around to
     1; this also avoids the verboten zero.  */
  if (last <= 0)
    last = 1;
  /* Now it may happen that after wrapping there is still a session id
     with that new value in use.  We can't allow that and check for
     it.  */
  for (i=0; i < DIM (session_table); i++)
    if (session_table[i].session_id == last)
      goto again;

  return last;
}


/* Return the port for an SSH connection.  It first looks up the port
   in the preferences, then falls back to the KB, and finally resorts
   to the standard port. */
static unsigned short
get_ssh_port (lex_ctxt *lexic)
{
  const char *value;
  char *port_str;
  int type;
  unsigned short port;

  value = prefs_get ("auth_port_ssh");
  if (value && (port = (unsigned short)strtoul (value, NULL, 10)) > 0)
    return port;

  port_str = plug_get_key (lexic->script_infos, "Services/ssh", &type, 0);
  if (port_str)
    {
      port = GPOINTER_TO_SIZE (port_str);
      g_free (port_str);
      if (type == KB_TYPE_INT && (port = GPOINTER_TO_SIZE (port_str)) > 0)
        return port;
    }

  return 22;
}

extern int lowest_socket;

/**
 * @brief Connect to the target host via TCP and setup an ssh
 *        connection.
 * @naslfn{ssh_connect}
 *
 * If the named argument "socket" is given, that socket will be used
 * instead of a creating a new TCP connection.  If socket is not given
 * or 0, the port is looked up in the preferences and the KB unless
 * overriden by the named parameter "port".
 *
 * On success an ssh session to the host has been established; the
 * caller may then run an authentication function.  If the connection
 * is no longer needed, ssh_disconnect may be used to disconnect and
 * close the socket.
 *
 * @naslnparam
 *
 * - @a socket If given, this socket will be used instead of creating
 *             a new connection.
 *
 * - @a port A non-standard port to connect to.  This is only used if
 *           @a socket is not given or 0.
 *
 * @naslret An integer to identify the ssh session. Zero on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with a non-zero
 *         integer identifying that ssh session; zero is returned on a
 *         connection error.  In case of an internal error NULL is
 *         returned.
 */
tree_cell *
nasl_ssh_connect (lex_ctxt *lexic)
{
  ssh_session session;
  tree_cell *retc;
  const char *hostname, *key_type, *csciphers, *scciphers;
  int port, sock;
  int tbl_slot;
  const char *s;
  int verbose = 0;
  int forced_sock = -1;

  sock = get_int_var_by_name (lexic, "socket", 0);
  if (sock)
    port = 0; /* The port is ignored if "socket" is given.  */
  else
    {
      port = get_int_var_by_name (lexic, "port", 0);
      if (port <= 0)
        port = get_ssh_port (lexic);
    }

  hostname = plug_get_hostname (lexic->script_infos);
  if (!hostname)
    {
      /* Note: We want the hostname even if we are working on an open
         socket.  libssh may use it for example to maintain its
         known_hosts file.  */
      log_legacy_write ("No hostname available to ssh_connect\n");
      return NULL;
    }

  session = ssh_new ();
  if (!session)
    {
      log_legacy_write ("Failed to allocate a new SSH session\n");
      return NULL;
    }

  if ((s = getenv ("OPENVAS_LIBSSH_DEBUG")))
    {
      verbose = 1;
      if (*s)
        {
          int intval = atoi (s);

          ssh_options_set (session, SSH_OPTIONS_LOG_VERBOSITY, &intval);
        }
    }

  if (ssh_options_set (session, SSH_OPTIONS_HOST, hostname))
    {
      log_legacy_write ("Failed to set SSH hostname '%s': %s\n",
                        hostname, ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  key_type = get_str_var_by_name (lexic, "keytype");
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT (0, 6, 0)
  if (key_type && ssh_options_set (session, SSH_OPTIONS_HOSTKEYS, key_type))
    {
      log_legacy_write ("Failed to set SSH key type '%s': %s",
                        key_type, ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }
#else
  if (key_type)
    {
      log_legacy_write ("SSH_OPTIONS_HOSTKEYS not supported");
      ssh_free (session);
      return NULL;
    }
#endif

  csciphers = get_str_var_by_name (lexic, "csciphers");
  if (csciphers && ssh_options_set (session, SSH_OPTIONS_CIPHERS_C_S, csciphers))
    {
      log_legacy_write ("Failed to set SSH client to server ciphers '%s': %s",
                        csciphers, ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }
  scciphers = get_str_var_by_name (lexic, "scciphers");
  if (scciphers && ssh_options_set (session, SSH_OPTIONS_CIPHERS_S_C, scciphers))
    {
      log_legacy_write ("Failed to set SSH server to client ciphers '%s': %s",
                        scciphers, ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  if (port)
    {
      unsigned int my_port = port;

      if (ssh_options_set (session, SSH_OPTIONS_PORT, &my_port))
        {
          log_legacy_write ("Failed to set SSH port for '%s' to %d: %s\n",
                            hostname, port, ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
    }
  if (sock)
    {
      socket_t my_fd = openvas_get_socket_from_connection (sock);

      if (verbose)
        log_legacy_write ("Setting SSH fd for '%s' to %d (NASL sock=%d)\n",
                          hostname, my_fd, sock);
      if (ssh_options_set (session, SSH_OPTIONS_FD, &my_fd))
        {
          log_legacy_write
           ("Failed to set SSH fd for '%s' to %d (NASL sock=%d): %s\n",
            hostname, my_fd, sock, ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
      /* Remember the NASL socket.  */
      forced_sock = sock;
    }

  /* Find a place in the table to save the session.  */
  for (tbl_slot=0; tbl_slot < DIM (session_table); tbl_slot++)
    if (!session_table[tbl_slot].session_id)
      break;
  if (!(tbl_slot < DIM (session_table)))
    {
      if (verbose)
        log_legacy_write ("No space left in SSH session table\n");
      ssh_free (session);
      return NULL;
    }

  /* Prepare the session table entry.  */
  session_table[tbl_slot].session = session;
  session_table[tbl_slot].authmethods_valid = 0;
  session_table[tbl_slot].user_set = 0;
  session_table[tbl_slot].verbose = verbose;

  /* Connect to the host.  */
  if (verbose)
    log_legacy_write ("Connecting to SSH server '%s' (port %d, sock %d)\n",
                      hostname, port, sock);
  if (ssh_connect (session))
    {
      if (verbose)
        log_legacy_write ("Failed to connect to SSH server '%s'"
                          " (port %d, sock %d, f=%d): %s\n", hostname, port,
                          sock, forced_sock, ssh_get_error (session));
      if (forced_sock != -1)
        {
          /* If the caller passed us a socket we can't call ssh_free
             on it because we expect the caller to close that socket
             himself.  Instead we need to setup a table entry so that
             it will then be close it via nasl_ssh_internal_close.  */
          session_table[tbl_slot].session_id = next_session_id ();
          session_table[tbl_slot].sock = forced_sock;
         }
     else
       ssh_free (session);

      /* return 0 to indicate the error.  */
      /* FIXME: Set the last error string.  */
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = 0;
      return retc;
    }

  /* How that we are connected, save the session.  */
  session_table[tbl_slot].session_id = next_session_id ();
  session_table[tbl_slot].sock =
    forced_sock != -1? forced_sock : ssh_get_fd (session);
  if (lowest_socket == 0 && session_table[tbl_slot].sock > 0)
    lowest_socket = session_table[tbl_slot].sock;

  /* Return the session id.  */
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_table[tbl_slot].session_id;
  return retc;
}


/* Helper function to find and validate the session id.  On error 0 is
   returned, on success the session id and in this case the slot number
   from the table is stored at R_SLOT.  */
static int
verify_session_id (int session_id, const char *funcname,
                   int *r_slot, lex_ctxt *lexic)
{
  int tbl_slot;
  if (session_id <= 0)
    {
      if (funcname)
        nasl_perror (lexic, "Invalid SSH session id %d passed to %s\n",
                          session_id, funcname);
      return 0;
    }
  for (tbl_slot=0; tbl_slot < DIM (session_table); tbl_slot++)
    if (session_table[tbl_slot].session_id == session_id)
      break;
  if (!(tbl_slot < DIM (session_table)))
    {
      if (funcname)
        nasl_perror (lexic, "Bad SSH session id %d passed to %s\n",
                          session_id, funcname);
      return 0;
    }

  *r_slot = tbl_slot;
  return session_id;
}


/* Helper for nasl_ssh_disconnect et al.  */
static void
do_nasl_ssh_disconnect (int tbl_slot)
{
  if (session_table[tbl_slot].channel)
    ssh_channel_free (session_table[tbl_slot].channel);
  ssh_disconnect (session_table[tbl_slot].session);
  ssh_free (session_table[tbl_slot].session);
  session_table[tbl_slot].session_id = 0;
  session_table[tbl_slot].session = NULL;
  session_table[tbl_slot].channel = NULL;
  session_table[tbl_slot].sock = -1;
}


/**
 * @brief Disconnect an ssh connection
 * @naslfn{ssh_disconnect}
 *
 * This function takes the ssh session id (as returned by ssh_connect)
 * as its only unnamed argument.  Passing 0 as session id is
 * explicitly allowed and does nothing.  If there are any open
 * channels they are closed as well and their ids will be marked as
 * invalid.
 *
 * @nasluparam
 *
 * - An ssh session id.  A value of 0 is allowed and acts as a NOP.
 *
 * @naslret Nothing
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Nothing.
 */
tree_cell *
nasl_ssh_disconnect (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, NULL, &tbl_slot, lexic))
    return FAKE_CELL;
  do_nasl_ssh_disconnect (tbl_slot);
  return FAKE_CELL;
}


/**
 * @brief Hook to close a socket associated with an ssh connection.
 *
 * NASL code may be using "ssh_connect" passing an open socket and
 * later closing this socket using "close" instead of calling
 * "ssh_disconnect".  Thus the close code needs to check whether the
 * socket refers to an ssh connection and call ssh_disconnect then
 * (libssh takes ownership of the socket if set via SSH_OPTIONS_FD).
 * This function implements the hook for checking and closing.
 *
 * @param[in] sock A socket
 *
 * @return Zero if the socket was closed (disconnected).
 */
static int
nasl_ssh_close_hook (int sock)
{
  int tbl_slot, session_id;

  if (sock == -1)
    return -1;

  session_id = 0;
  for (tbl_slot=0; tbl_slot < DIM (session_table); tbl_slot++)
    {
      if (session_table[tbl_slot].sock == sock
          && session_table[tbl_slot].session_id) {
        session_id = session_table[tbl_slot].session_id;
        break;
      }
    }
  if (!session_id)
    return -1;
  do_nasl_ssh_disconnect (tbl_slot);
  return 0;
}


/**
 * @brief Given a socket, return the corresponding session id.
 * @naslfn{ssh_session_id_from_sock}
 * @nasluparam
 * - A NASL socket value
 *
 * @naslret An integer with the corresponding ssh session id or 0 if
 *          no session id is known for the given socket.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The session id on success or 0 if not found.
 */
tree_cell *
nasl_ssh_session_id_from_sock (lex_ctxt *lexic)
{
  int tbl_slot, sock, session_id;
  tree_cell *retc;

  session_id = 0;
  sock = get_int_var_by_num (lexic, 0, -1);
  if (sock != -1)
    {
      for (tbl_slot=0; tbl_slot < DIM (session_table); tbl_slot++)
        if (session_table[tbl_slot].sock == sock
            && session_table[tbl_slot].session_id) {
          session_id = session_table[tbl_slot].session_id;
          break;
        }
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_id;
  return retc;
}


/**
 * @brief Given a session id, return the corresponding socket
 * @naslfn{ssh_get_sock}
 *
 * The socket is either a native file descriptor or a NASL connection
 * socket (if a open socket was passed to ssh_connect).  The NASL
 * network code handles both of them.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret An integer representing the socket or -1 on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The socket or -1 on error.
 */
tree_cell *
nasl_ssh_get_sock (lex_ctxt *lexic)
{
  int tbl_slot, sock, session_id;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_sock", &tbl_slot, lexic))
    sock = -1;
  else
    sock = session_table[tbl_slot].sock;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = sock;
  return retc;
}


/* Get the list of supported authentication schemes.  Returns 0 if no
   authentication is required; otherwise non-zero.  */
static int
get_authmethods (int tbl_slot)
{
  int rc;
  int retc_val = -1;
  ssh_session session;
  int verbose;
  int methods;

  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  rc = ssh_userauth_none (session, NULL);
  if (rc == SSH_AUTH_SUCCESS)
    {
      log_legacy_write ("SSH authentication succeeded using the none method - "
                        "should not happen; very old server?\n");
      retc_val = 0;
      methods = 0;
      goto leave;
    }
  else if (rc == SSH_AUTH_DENIED)
    {
      methods = ssh_userauth_list (session, NULL);
    }
  else
    {
      if (verbose)
        log_legacy_write
         ("SSH server did not return a list of authentication methods"
          " - trying all\n");
      methods = (SSH_AUTH_METHOD_NONE
                 | SSH_AUTH_METHOD_PASSWORD
                 | SSH_AUTH_METHOD_PUBLICKEY
                 | SSH_AUTH_METHOD_HOSTBASED
                 | SSH_AUTH_METHOD_INTERACTIVE);
    }

  if (verbose)
    {
      fputs ("SSH available authentication methods:", stderr);
      if ((methods & SSH_AUTH_METHOD_NONE))
        fputs (" none", stderr);
      if ((methods & SSH_AUTH_METHOD_PASSWORD))
        fputs (" password", stderr);
      if ((methods & SSH_AUTH_METHOD_PUBLICKEY))
        fputs (" publickey", stderr);
      if ((methods & SSH_AUTH_METHOD_HOSTBASED))
        fputs (" hostbased", stderr);
      if ((methods & SSH_AUTH_METHOD_INTERACTIVE))
        fputs (" keyboard-interactive", stderr);
      fputs ("\n", stderr);
    }

 leave:
  session_table[tbl_slot].authmethods = methods;
  session_table[tbl_slot].authmethods_valid = 1;

  return retc_val;
}


/**
 * @brief Set the login name for the authentication.
 * @naslfn{ssh_set_login}
 *
 * This is an optional function and usuallay not required.  However,
 * if you want to get the banner before starting the authentication,
 * you need to tell libssh the user because it is often not possible
 * to chnage the user after the first call to an authentication
 * methods - getting the banner usees an authntication function.
 *
 * The named argument "login" is used for the login name; it defaults
 * the KB entry "Secret/SSH/login".  It should contain the user name
 * to login.  Given that many servers don't allow changing the login
 * for an established connection, the "login" parameter is silently
 * ignored on all further calls.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslnparam
 *
 * - @a login A string with the login name (optional).
 *
 * @naslret None
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return none.
 */
tree_cell *
nasl_ssh_set_login (lex_ctxt *lexic)
{
  int tbl_slot, session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_set_login", &tbl_slot, lexic))
    return NULL;  /* Ooops.  */
  if (!session_table[tbl_slot].user_set)
    {
      ssh_session session = session_table[tbl_slot].session;
      kb_t kb;
      char *username;

      username = get_str_var_by_name (lexic, "login");
      if (!username)
        {
          kb = plug_get_kb (lexic->script_infos);
          username = kb_item_get_str (kb, "Secret/SSH/login");
        }
      if (username && *username &&
          ssh_options_set (session, SSH_OPTIONS_USER, username))
        {
          log_legacy_write ("Failed to set SSH username '%s': %s\n",
                            username, ssh_get_error (session));
          return NULL; /* Ooops.  */
        }
      /* In any case mark the user has set.  */
      session_table[tbl_slot].user_set = 1;
    }
  return FAKE_CELL;
}


/**
 * @brief Authenticate a user on an ssh connection
 * @naslfn{ssh_userauth}
 *
 * The function expects the session id as its first unnamed argument.
 * The first time this function is called for a session id, the named
 * argument "login" is also expected; it defaults the KB entry
 * "Secret/SSH/login".  It should contain the user name to login.
 * Given that many servers don't allow changing the login for an
 * established connection, the "login" parameter is silently ignored
 * on all further calls.
 *
 * To perform a password based authentication, the named argument
 * "password" must contain a password.
 *
 * To perform a public key based authentication, the named argument
 * "privatekey" must contain a base64 encoded private key in ssh
 * native or in PKCS#8 format.
 *
 * If both, "password" and "privatekey" are given as named arguments
 * only "password" is used.  If neither are given the values are taken
 * from the KB ("Secret/SSH/password" and "Secret/SSH/privatekey") and
 * tried in the order {password, privatekey}.  Note well, that if one
 * of the named arguments are given, only those are used and the KB is
 * not consulted.
 *
 * If the private key is protected, its passphrase is taken from the
 * named argument "passphrase" or, if not given, taken from the KB
 * ("Secret/SSH/passphrase").
 *
 * Note that the named argument "publickey" and the KB item
 * ("Secret/SSH/publickey") are ignored - they are not longer required
 * because they can be derived from the private key.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslnparam
 *
 * - @a login A string with the login name.
 *
 * - @a password A string with the password.
 *
 * - @a privatekey A base64 encoded private key in ssh native or in
 *      pkcs#8 format.  This parameter is ignored if @a password is given.
 *
 * - @a passphrase A string with the passphrase used to unprotect @a
 *      privatekey.
 *
 * @naslret An integer as status value; 0 indicates success.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return 0 is returned on success.  Any other value indicates an
 *         error.
 */
tree_cell *
nasl_ssh_userauth (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  const char *password = NULL;
  const char *privkeystr = NULL;
  const char *privkeypass = NULL;
  int rc;
  kb_t kb;
  int retc_val = -1;
  int methods;
  int verbose;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_userauth", &tbl_slot, lexic))
    return NULL;  /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  /* Check if we need to set the user.  This is done only once per
     session.  */
  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;

  kb = plug_get_kb (lexic->script_infos);
  password = get_str_var_by_name (lexic, "password");
  privkeystr = get_str_var_by_name (lexic, "privatekey");
  privkeypass = get_str_var_by_name (lexic, "passphrase");
  if (!password && !privkeystr && !privkeypass)
    {
      password = kb_item_get_str (kb, "Secret/SSH/password");
      privkeystr = kb_item_get_str (kb, "Secret/SSH/privatekey");
      privkeypass = kb_item_get_str (kb, "Secret/SSH/passphrase");
    }

  /* Get the authentication methods onlye once per session.  */
  if (!session_table[tbl_slot].authmethods_valid)
    {
      if (!get_authmethods (tbl_slot))
        {
          retc_val = 0;
          goto leave;
        }
    }
  methods = session_table[tbl_slot].authmethods;

  /* Check whether a password has been given.  If so, try to
     authenticate using that password.  Note that the OpenSSH client
     uses a different order it first tries the public key and then the
     password.  However, the old NASL SSH protocol implementation tries
     the password before the public key authentication.  Because we
     want to be compatible, we do it in that order. */
  if (password && (methods & SSH_AUTH_METHOD_PASSWORD))
    {
      rc = ssh_userauth_password (session, NULL, password);
      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }

      if (verbose)
        log_legacy_write ("SSH password authentication failed for session"
                          " %d: %s\n", session_id, ssh_get_error (session));
      /* Keep on trying.  */
    }

  if (password && (methods & SSH_AUTH_METHOD_INTERACTIVE))
    {
      /* Our strategy for kbint is to send the password to the first
         prompt marked as non-echo.  */
      while ((rc = ssh_userauth_kbdint (session, NULL, NULL)) == SSH_AUTH_INFO)
        {
          const char *s;
          int n, nprompt;
          char echoflag;
          int found_prompt = 0;

          if (verbose)
            {
              s = ssh_userauth_kbdint_getname (session);
              if (s && *s)
                log_legacy_write ("SSH kbdint name='%s'\n", s);
              s = ssh_userauth_kbdint_getinstruction (session);
              if (s && *s)
                log_legacy_write ("SSH kbdint instruction='%s'\n", s);
            }
          nprompt = ssh_userauth_kbdint_getnprompts (session);
          for (n=0; n < nprompt; n++)
            {
              s = ssh_userauth_kbdint_getprompt (session, n, &echoflag);
              if (s && *s && verbose)
                log_legacy_write ("SSH kbdint prompt='%s'%s\n",
                                  s, echoflag ? "" : " [hide input]");
              if (s && *s && !echoflag && !found_prompt)
                {
                  found_prompt = 1;
                  rc = ssh_userauth_kbdint_setanswer (session, n, password);
                  if (rc != SSH_AUTH_SUCCESS)
                    {
                      if (verbose)
                        log_legacy_write
                         ("SSH keyboard-interactive authentication "
                          "failed at prompt %d for session %d: %s\n",
                          n, session_id, ssh_get_error (session));
                    }
                }
            }
        }

      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }

      if (verbose)
        log_legacy_write
         ("SSH keyboard-interactive authentication failed for session %d"
          ": %s\n", session_id, ssh_get_error (session));
      /* Keep on trying.  */
    }

  /* If we have a private key, try public key authentication.  */
  if (privkeystr && *privkeystr && (methods & SSH_AUTH_METHOD_PUBLICKEY))
    {
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT (0, 6, 0)
      ssh_key key = NULL;

      if (ssh_pki_import_privkey_base64 (privkeystr, privkeypass, NULL, NULL,
                                         &key))
        {
          if (verbose)
            log_legacy_write
             ("SSH public key authentication failed for "
              "session %d: %s\n", session_id, "Error converting provided key");
        }
      else if (ssh_userauth_try_publickey (session, NULL, key)
               != SSH_AUTH_SUCCESS)
        {
          if (verbose)
            log_legacy_write
             ("SSH public key authentication failed for "
              "session %d: %s\n", session_id, "Server does not want our key");
        }
      else if (ssh_userauth_publickey (session, NULL, key) == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          ssh_key_free (key);
          goto leave;
        }
      ssh_key_free (key);

#else

      my_ssh_key key = NULL;

      /* SESSION is only used by our emulation - FIXME: remove it for 0.6.  */
      if (my_ssh_pki_import_privkey_base64 (session, verbose,
                                            privkeystr, privkeypass,
                                            NULL, NULL, &key))
        {
          if (verbose)
            log_legacy_write
             ("SSH public key authentication failed for "
              "session %d: %s\n", session_id, "Error converting provided key");
        }
      else if (my_ssh_userauth_try_publickey (session, NULL, key)
               != SSH_AUTH_SUCCESS)
        {
          if (verbose)
            log_legacy_write
             ("SSH public key authentication failed for "
              "session %d: %s\n", session_id, "Server does not want our key");
        }
      else if (my_ssh_userauth_publickey (session, NULL, key)
               == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          my_ssh_key_free (key);
          goto leave;
        }
      my_ssh_key_free (key);
#endif
      /* Keep on trying.  */
    }

  if (verbose)
    log_legacy_write ("SSH authentication failed for session %d: %s\n",
                      session_id, "No more authentication methods to try");
 leave:
  {
    tree_cell *retc;

    retc = alloc_typed_cell (CONST_INT);
    retc->x.i_val = retc_val;
    return retc;
  }
}


/**
 * @brief Authenticate a user on an ssh connection
 * @naslfn{ssh_login_intenteractive}
 *
 * The function starts the authentication process and pauses it when
 * it finds the first non-echo prompt. The function expects the session
 * id as its first unnamed argument.
 * The first time this function is called for a session id, the named
 * argument "login" is also expected.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslnparam
 *
 * - @a login A string with the login name.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string containing the prompt is returned on success.
 *         NULL indicates that the error.
 */
tree_cell *
nasl_ssh_login_interactive (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  int rc;
  const char *s = NULL;
  int methods;
  int verbose;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_login_interactive",
                          &tbl_slot, lexic))
    return NULL;  /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  /* Check if we need to set the user.  This is done only once per
     session.  */
  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;

  /* Get the authentication methods onlye once per session.  */
  if (!session_table[tbl_slot].authmethods_valid)
    {
      if (!get_authmethods (tbl_slot))
        {
          s = g_strdup ("");
          goto leave;
        }
    }
  methods = session_table[tbl_slot].authmethods;

  if (methods & SSH_AUTH_METHOD_INTERACTIVE)
    {
      /* Our strategy for kbint is to send the password to the first
         prompt marked as non-echo.  */
      while ((rc = ssh_userauth_kbdint (session, NULL, NULL)) == SSH_AUTH_INFO)
        {
          int n, nprompt;
          char echoflag;
          int found_prompt = 0;

          if (verbose)
            {
              s = ssh_userauth_kbdint_getname (session);
              if (s && *s)
                g_message ("SSH kbdint name='%s'", s);
              s = ssh_userauth_kbdint_getinstruction (session);
              if (s && *s)
                g_message ("SSH kbdint instruction='%s'", s);
            }

          nprompt = ssh_userauth_kbdint_getnprompts (session);
          for (n=0; n < nprompt; n++)
            {
              s = ssh_userauth_kbdint_getprompt (session, n, &echoflag);
              if (s && *s && verbose)
                g_message ("SSH kbdint prompt='%s'%s",
                           s, echoflag ? "" : " [hide input]");
              if (s && *s && !echoflag && !found_prompt)
                goto leave;
            }
        }
      if (verbose)
        g_message
          ("SSH keyboard-interactive authentication failed for session %d"
           ": %s", session_id, ssh_get_error (session));
    }

  if (!s)
    return NULL;

 leave:
  {
    tree_cell *retc;

    retc = alloc_typed_cell (CONST_DATA);
    retc->x.str_val = g_strdup (s);
    retc->size = strlen (s);
    return retc;
  }
}


/**
 * @brief Authenticate a user on an ssh connection
 * @naslfn{ssh_login_intenteractive_pass}
 *
 * The function finishes the authentication process started by
 * ssh_login_interactive. The function expects the session id as its first
 * unnamed argument.
 *
 * To finish the password, the named argument "password" must contain
 * a password.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslnparam
 *
 * - @a password A string with the password.
 *
 * @naslret An integer as status value; 0 indicates success.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return An integer is returned on success. -1 indicates an
 *         error.
 */
tree_cell *
nasl_ssh_login_interactive_pass (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  const char *password = NULL;
  int rc;
  int retc_val = -1;
  int verbose;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_login_interactive_pass",
                          &tbl_slot, lexic))
    return NULL;  /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;

  /* A prompt is waiting for the password. */
  if ((password = get_str_var_by_name (lexic, "password")) == NULL)
    return NULL;

  rc = ssh_userauth_kbdint_setanswer (session, 0, password);

  if (rc < 0)
    {
      if (verbose)
        g_message ("SSH keyboard-interactive authentication "
                   "failed at prompt %d for session %d: %s",
                   0, session_id, ssh_get_error (session));
      retc_val = -1;
      goto leave;
    }

  if (rc == 0)
    {
      /* I need to do that to finish the auth process. */
      while ((rc = ssh_userauth_kbdint (session, NULL, NULL)) == SSH_AUTH_INFO)
        {
          ssh_userauth_kbdint_getnprompts (session);
        }
      if (rc == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          goto leave;
        }
      if (rc != SSH_AUTH_SUCCESS)
        {
          retc_val = -1;
          goto leave;
        }
    }

 leave:
  {
    tree_cell *retc;

    retc = alloc_typed_cell (CONST_INT);
    retc->x.i_val = retc_val;
    return retc;
  }
}


static void
exec_ssh_cmd_alarm (int signal)
{
  log_legacy_write ("exec_ssh_cmd: Timeout");
}

/**
 * @brief Execute an ssh command.
 *
 * @param[in]   session     SSH session.
 * @param[in]   cmd         Command to execute.
 * @param[in]   verbose     1 for verbose mode, 0 otherwise.
 * @param[in]   compat_mode 1 for compatibility mode, 0 otherwise.
 * @param[in]   to_stdout   1 to return command output to stdout.
 * @param[in]   to_stderr   1 to return command output to stderr.
 * @param[out]  response    Response buffer.
 * @param[out]  compat_buf  Compatibility buffer.
 *
 *
 * @return SSH_OK if success, SSH_ERROR otherwise.
 */
static int
exec_ssh_cmd (ssh_session session, char *cmd, int verbose, int compat_mode,
              int to_stdout, int to_stderr, GString *response,
              GString *compat_buf)
{
  int rc, retry = 60;
  ssh_channel channel;

  /* Work-around for LibSSH calling poll() with an infinite timeout. */
  signal (SIGALRM, exec_ssh_cmd_alarm);
  alarm (30);
  if ((channel = ssh_channel_new (session)) == NULL)
    {
      log_legacy_write ("ssh_channel_new failed: %s\n",
                        ssh_get_error (session));
      return SSH_ERROR;
    }

  if (ssh_channel_open_session (channel))
    {
      /* FIXME: Handle SSH_AGAIN.  */
      if (verbose)
        log_legacy_write ("ssh_channel_open_session failed: %s\n",
                          ssh_get_error (session));
      ssh_channel_free (channel);
      return SSH_ERROR;
    }

  if (ssh_channel_request_pty (channel) && verbose)
    g_message ("ssh_channel_request_pty failed: %s", ssh_get_error (session));

  if (ssh_channel_request_exec (channel, cmd))
    {
      /* FIXME: Handle SSH_AGAIN.  */
      if (verbose)
        log_legacy_write ("ssh_channel_request_exec failed for '%s': %s\n",
                          cmd, ssh_get_error (session));
      ssh_channel_free (channel);
      return SSH_ERROR;
    }
  alarm (0);
  signal (SIGALRM, _exit);
  /* XXX: ssh_channel_read_timeout() is available for LIBSSH > 0.6. */
  while (ssh_channel_is_open (channel) && !ssh_channel_is_eof (channel)
         && retry-- > 0)
    {
      char buffer[4096];

      memset (buffer, '\0', sizeof (buffer));
      if ((rc = ssh_channel_read_nonblocking
                 (channel, buffer, sizeof (buffer), 1)) > 0)
        {
          if (to_stderr)
            g_string_append_len (response, buffer, rc);
          if (compat_mode)
            g_string_append_len (compat_buf, buffer, rc);
        }
      if (rc == SSH_ERROR)
        goto exec_err;
      if ((rc = ssh_channel_read_nonblocking
                 (channel, buffer, sizeof (buffer), 0)) > 0)
        {
          compat_mode = 0;
          if (to_stdout)
            g_string_append_len (response, buffer, rc);
        }
      if (rc == SSH_ERROR)
        goto exec_err;
      if (*buffer)
        retry = 60;
      else
        usleep (250000);
    }
  rc = SSH_OK;

exec_err:
  ssh_channel_free (channel);
  return rc;
}

/**
 * @brief Run a command via ssh.
 * @naslfn{ssh_request_exec}
 *
 * The function opens a channel to the remote end and ask it to
 * execute a command.  The output of the command is then returned as a
 * data block.  The first unnamed argument is the session id. The
 * command itself is expected as string in the named argument "cmd".
 *
 * Regarding the handling of the stderr and stdout stream, this
 * function may be used in different modes.
 *
 * If either the named arguments @a stdout or @a stderr are given and
 * that one is set to 1, only the output of the specified stream is
 * returned.
 *
 * If @a stdout and @a stderr are both given and set to 1, the output
 * of both is returned interleaved.  NOTE: The following feature has
 * not yet been implemented: The output is guaranteed not to switch
 * between stderr and stdout within a line.
 *
 * If @a stdout and @a stderr are both given but set to 0, a special
 * backward compatibility mode is used: First all output to stderr is
 * collected up until any output to stdout is received.  Then all
 * output to stdout is returned while ignoring all further stderr
 * output; at EOF the initial collected data from stderr is returned.
 *
 * If the named parameters @a stdout and @a stderr are not given, the
 * function acts exactly as if only @a stdout has been set to 1.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslnparam
 *
 * - @a cmd A string with the command to execute.
 *
 * - @a stdout An integer with value 0 or 1; see above for a full
 *    description.
 *
 * - @a stderr An integer with value 0 or 1; see above for a full
 *    description.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A data/string is returned on success.  NULL indicates an
 *         error.
 */
tree_cell *
nasl_ssh_request_exec (lex_ctxt *lexic)
{
  int tbl_slot;
  int session_id;
  ssh_session session;
  int verbose;
  char *cmd;
  int rc;
  GString *response, *compat_buf;
  size_t len = 0;
  tree_cell *retc;
  char *p;
  int to_stdout, to_stderr, compat_mode, compat_buf_inuse;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_request_exec", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  verbose = session_table[tbl_slot].verbose;

  cmd = get_str_var_by_name (lexic, "cmd");
  if (!cmd || !*cmd)
    {
      log_legacy_write ("No command passed to ssh_request_exec\n");
      return NULL;
    }

  to_stdout = get_int_var_by_name (lexic, "stdout", -1);
  to_stderr = get_int_var_by_name (lexic, "stderr", -1);
  compat_mode = 0;
  if (to_stdout == -1 && to_stderr == -1)
    {
      /* None of the two named args are given.  */
      to_stdout = 1;
    }
  else if (to_stdout == 0 && to_stderr == 0)
    {
      /* Compatibility mode.  */
      to_stdout = 1;
      compat_mode = 1;
    }

  if (to_stdout < 0)
    to_stdout = 0;
  if (to_stderr < 0)
    to_stderr = 0;


  memset (&compat_buf, '\0', sizeof (compat_buf));
  /* Allocate some space in advance.  Most commands won't output too
     much and thus 512 bytes (6 standard terminal lines) should often
     be sufficient.  */
  response = g_string_sized_new (512);
  if (compat_mode)
    {
      compat_buf = g_string_sized_new (512);
      compat_buf_inuse = 1;
    }
  else
    compat_buf_inuse = 0;

  rc = exec_ssh_cmd (session, cmd, verbose, compat_mode, to_stdout, to_stderr,
                     response, compat_buf);
  if (rc == SSH_ERROR)
    {
      if (compat_buf_inuse)
        g_string_free (compat_buf, TRUE);
      g_string_free (response, TRUE);
      return NULL;
    }

  /* Append the compatibility buffer to the output.  */
  if (compat_buf_inuse)
    {
      len = compat_buf->len;
      p = g_string_free (compat_buf, FALSE);
      if (p)
        {
          g_string_append_len (response, p, len);
          g_free (p);
        }
    }

  /* Return the the output.  */
  len = response->len;
  p = g_string_free (response, FALSE);
  if (!p)
    {
      log_legacy_write ("ssh_request_exec memory problem: %s\n", strerror (-1));
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = p;
  return retc;
}


/**
 * @brief Get the issue banner
 * @naslfn{ssh_get_issue_banner}
 *
 * The function returns a string with the issue banner.  This is
 * usually displayed before authentication.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         server did not send a banner or that the connection has not
 *         yet been established.
 */
tree_cell *
nasl_ssh_get_issue_banner (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_session session;
  char *banner;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_issue_banner", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  /* We need to make sure that we got the auth methods so that libssh
     has the banner.  */
  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;
  if (!session_table[tbl_slot].authmethods_valid)
    get_authmethods (tbl_slot);

  banner = ssh_get_issue_banner (session);
  if (!banner)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = g_strdup (banner);
  retc->size = strlen (banner);
  ssh_string_free_char (banner);
  return retc;
}


#if LIBSSH_VERSION_INT >= SSH_VERSION_INT (0, 6, 0)
/**
 * @brief Get the server banner
 * @naslfn{ssh_get_server_banner}
 *
 * The function returns a string with the server banner.  This is
 * usually the first data sent by the server.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         connection has not yet been established.
 */
tree_cell *
nasl_ssh_get_server_banner (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_session session;
  const char *banner;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_server_banner",
                          &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  banner = ssh_get_serverbanner (session);
  if (!banner)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = g_strdup (banner);
  retc->size = strlen (banner);
  return retc;
  (void)lexic;
  return NULL;
}
#endif

/**
 * @brief Get the host key
 * @naslfn{ssh_get_host_key}
 *
 * The function returns a string with the MD5 host key. *
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret A data block on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         connection has not yet been established.
 */
tree_cell *
nasl_ssh_get_host_key (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_session session;
  ssh_string sstring;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_host_key", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;

  sstring = ssh_get_pubkey (session);
  if (!sstring)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = ssh_string_to_char (sstring);
  retc->size = ssh_string_len (sstring);
  ssh_string_free (sstring);
  return retc;
}

/**
 * @brief Get the list of authmethods
 * @naslfn{ssh_get_auth_methods}
 *
 * The function returns a string with comma separated authentication
 * methods.  This is basically the same as returned by
 * SSH_MSG_USERAUTH_FAILURE protocol element; however, it has been
 * screened and put into a definitive order.
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret A string on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return A string is returned on success.  NULL indicates that the
 *         connection has not yet been established.
 */
tree_cell *
nasl_ssh_get_auth_methods (lex_ctxt *lexic)
{
  int tbl_slot, methods, session_id;
  GString *buffer;
  char *p;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_get_auth_methods", &tbl_slot, lexic))
    return NULL;

  if (!session_table[tbl_slot].user_set && !nasl_ssh_set_login (lexic))
    return NULL;
  if (!session_table[tbl_slot].authmethods_valid)
    get_authmethods (tbl_slot);

  methods = session_table[tbl_slot].authmethods;

  buffer = g_string_sized_new (128);
  if ((methods & SSH_AUTH_METHOD_NONE))
    g_string_comma_str (buffer, "none");
  if ((methods & SSH_AUTH_METHOD_PASSWORD))
    g_string_comma_str (buffer, "password");
  if ((methods & SSH_AUTH_METHOD_PUBLICKEY))
    g_string_comma_str (buffer, "publickey");
  if ((methods & SSH_AUTH_METHOD_HOSTBASED))
    g_string_comma_str (buffer, "hostbased");
  if ((methods & SSH_AUTH_METHOD_INTERACTIVE))
    g_string_comma_str (buffer, "keyboard-interactive");
  g_string_append_c (buffer, 0x00);
  p = g_string_free (buffer, FALSE);
  if (!p)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = p;
  retc->size = strlen (p);
  return retc;
}

static void
request_ssh_shell_alarm (int signal)
{
  log_legacy_write ("request_ssh_shell: Timeout");
}

/**
 * @brief Open a shell on an ssh channel.
 *
 * @param[in]   channel     SSH Channel.
 *
 * @return 0 if success, -1 if error.
 */
static int
request_ssh_shell (ssh_channel channel)
{
  assert (channel);

  /* Work-around for LibSSH calling poll() with an infinite timeout. */
  signal (SIGALRM, request_ssh_shell_alarm);
  alarm (30);
  if (ssh_channel_request_pty (channel))
    return -1;
  if (ssh_channel_change_pty_size (channel, 80, 24))
    return -1;
  if (ssh_channel_request_shell (channel))
    return -1;
  alarm (0);
  signal (SIGALRM, _exit);

  return 0;
}

/**
 * @brief Request an ssh shell.
 * @naslfn{ssh_shell_open}
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret An int on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Session ID on success, NULL on failure.
 */
tree_cell *
nasl_ssh_shell_open (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_channel channel;
  ssh_session session;
  tree_cell *retc;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_open", &tbl_slot, lexic))
    return NULL;
  session = session_table[tbl_slot].session;
  channel = ssh_channel_new (session);
  if (!channel)
    return NULL;
  if (ssh_channel_open_session (channel))
    {
      log_legacy_write ("ssh_channel_open_session: %s",
                        ssh_get_error (session));
      ssh_channel_free (channel);
      return NULL;
    }

  if (request_ssh_shell (channel))
    {
      log_legacy_write ("request_ssh_shell: %s", ssh_get_error (session));
      ssh_channel_free (channel);
      return NULL;
    }
  if (session_table[tbl_slot].channel)
    ssh_channel_free (session_table[tbl_slot].channel);
  session_table[tbl_slot].channel = channel;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_table[tbl_slot].session_id;
  return retc;
}

/**
 * @brief read from an ssh channel without blocking.
 *
 * @param[in]   channel     SSH Channel.
 * @param[out]  response    Buffer to store response in.
 *
 * @return 0 if success, -1 if error.
 */
static int
read_ssh_nonblocking (ssh_channel channel, GString *response)
{
  int rc;
  char buffer[4096];

  if (!ssh_channel_is_open (channel) || ssh_channel_is_eof (channel))
    return -1;

  if ((rc = ssh_channel_read_nonblocking
             (channel, buffer, sizeof (buffer), 1)) > 0)
    g_string_append_len (response, buffer, rc);
  if (rc == SSH_ERROR)
    return -1;
  if ((rc = ssh_channel_read_nonblocking
             (channel, buffer, sizeof (buffer), 0)) > 0)
    g_string_append_len (response, buffer, rc);
  if (rc == SSH_ERROR)
    return -1;
  return 0;
}

/**
 * @brief Read the output of an ssh shell.
 * @naslfn{ssh_shell_read}
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @naslret A string on success or NULL on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Data read from shell on success, NULL on failure.
 */
tree_cell *
nasl_ssh_shell_read (lex_ctxt *lexic)
{
  int tbl_slot, session_id;
  ssh_channel channel;
  tree_cell *retc;
  GString *response;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_read", &tbl_slot, lexic))
    return NULL;
  channel = session_table[tbl_slot].channel;

  response = g_string_new (NULL);
  if (read_ssh_nonblocking (channel, response))
    return NULL;
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = response->len;
  retc->x.str_val = g_string_free (response, FALSE);
  return retc;
}

/**
 * @brief Write string to ssh shell.
 * @naslfn{ssh_shell_write}
 *
 * @nasluparam
 *
 * - An ssh session id.
 * - A string to write to shell.
 *
 * @naslret An integer: 0 on success, -1 on failure.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return 0 on success, -1 on failure.
 */
tree_cell *
nasl_ssh_shell_write (lex_ctxt *lexic)
{
  int tbl_slot, rc = -1, len, session_id;
  ssh_channel channel;
  tree_cell *retc;
  char *cmd;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_write", &tbl_slot, lexic))
    goto write_ret;
  if (!(channel = session_table[tbl_slot].channel))
    {
      log_legacy_write ("ssh_shell_write: No shell channel found");
      goto write_ret;
    }

  cmd = get_str_var_by_name (lexic, "cmd");
  if (!cmd || !*cmd)
    {
      log_legacy_write ("ssh_shell_write: No command passed");
      goto write_ret;
    }
  len = strlen (cmd);
  if (ssh_channel_write (channel, cmd, len) != len)
    {
      log_legacy_write ("ssh_shell_write: %s",
                        ssh_get_error (session_table[tbl_slot].session));
      goto write_ret;
    }
  rc = 0;

write_ret:
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = rc;
  return retc;
}

/**
 * @brief Close an ssh shell.
 * @naslfn{ssh_shell_close}
 *
 * @nasluparam
 *
 * - An ssh session id.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 */
tree_cell *
nasl_ssh_shell_close (lex_ctxt *lexic)
{
  int tbl_slot, session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (!verify_session_id (session_id, "ssh_shell_close", &tbl_slot, lexic))
    return NULL;
  if (session_table[tbl_slot].channel)
    {
      ssh_channel_free (session_table[tbl_slot].channel);
      session_table[tbl_slot].channel = NULL;
    }

  return NULL;
}
