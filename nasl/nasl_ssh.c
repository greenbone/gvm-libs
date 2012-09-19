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

#include <gnutls/gnutls.h>      /* Used to convert pkcs8 to ssh format.  */
#include <gnutls/x509.h>

#include <libssh/libssh.h>
#include <libssh/legacy.h>      /* Remove for libssh 0.6.  */

#include "system.h"             /* for emalloc */
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "plugutils.h"
#include "kb.h"
#include "nasl_debug.h"

#include "nasl_ssh.h"


#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
# define DIMof(type,member)   DIM(((type *)0)->member)
#endif


#if SSH_OK != 0
# error Oops, libssh ABI changed
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
  int sock;                 /* The associated socket. */
  unsigned int user_set:1;  /* Set if a user has been set for the
                               session.  */
  unsigned int verbose:1;   /* Verbose diagnostics.  */
};


#define MAX_SSH_SESSIONS 10
static struct session_table_item_s session_table[MAX_SSH_SESSIONS];



/* A simple implementation of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  The code has been lifted from
   GnuPG; it was entirely written by me <wk@gnupg.org>.  It is
   licensed under LGPLv3+ or GPLv2+.  We use it here to avoid g_string
   which has the disadvange that we can't use the emalloc functions
   and thus need to copy the result again. */

/* The definition of the structure is private, we only need it here,
   so it can be allocated on the stack. */
struct private_membuf_s
{
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};

typedef struct private_membuf_s membuf_t;

static void
init_membuf (membuf_t *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = emalloc (initiallen);
  if (!mb->buf)
    mb->out_of_core = errno;
}


static void
put_membuf (membuf_t *mb, const void *buf, size_t len)
{
  if (mb->out_of_core || !len)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;

      mb->size += len + 1024;
      p = erealloc (mb->buf, mb->size);
      if (!p)
        {
          mb->out_of_core = errno ? errno : ENOMEM;
          return;
        }
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}


static void
put_membuf_byte (membuf_t *mb, unsigned char c)
{
  put_membuf (mb, &c, 1);
}


static void *
get_membuf (membuf_t *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      if (mb->buf)
        {
          efree (&mb->buf);
        }
      errno = mb->out_of_core;
      return NULL;
    }

  p = mb->buf;
  if (len)
    *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = ENOMEM; /* Hack to make sure it won't get reused. */
  return p;
}


/* Wrapper functions to make a future migration to the libssh 0.6 API
   easier.  The idea is that you only need to remove these wrappers
   and s/my_ssh_/ssh_/ on this file.  */

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


/* Create a TLV tag and store it at BUFFER.  A LENGTH greater than
   65535 is truncated.  This is used to write DER encoded data.  */
static void
add_tl (membuf_t *buffer, unsigned int tag, size_t length)
{
  g_assert (tag <= 0xffff);
  if (tag > 0xff)
    put_membuf_byte (buffer, tag >> 8);
  put_membuf_byte (buffer, tag);
  if (length < 128)
    put_membuf_byte (buffer, length);
  else if (length < 256)
    {
      put_membuf_byte (buffer, 0x81);
      put_membuf_byte (buffer, length);
    }
  else
    {
      if (length > 0xffff)
        length = 0xffff;
      put_membuf_byte (buffer, 0x82);
      put_membuf_byte (buffer, length >> 8);
      put_membuf_byte (buffer, length);
    }
}


/* Create a TLV tag and value and store it at BUFFER.  A LENGTH
   greater than 65535 is truncated.  This is used to write DER encoded
   data.  */
static void
add_tlv (membuf_t *buffer, unsigned int tag, void *value, size_t length)
{
  add_tl (buffer, tag, length);
  put_membuf (buffer, value, length);
}


/* Assume the PEM object in SSHPRIVKEYSTR is a pkcs#8 private RSA key
   and convert it into the standard ssh format without any protection.
   PASSPHRASE is the passphrase for the pkcs#8 object.  Note that we
   only support RSA here. */
static char *
pkcs8_to_sshprivatekey (const char *sshprivkeystr, const char *passphrase)
{
  int rc;
  gnutls_datum_t sshkey;
  gnutls_x509_privkey_t key;
  gnutls_datum_t m, e, d, p, q, u, dmp1, dmq1;
  membuf_t dermb;
  void *derbuf;
  size_t derlen;
  gnutls_datum_t der, pem;

  rc = gnutls_x509_privkey_init (&key);
  if (rc)
    {
      fprintf (stderr, "gnutls key init failed: %s\n", gnutls_strerror (rc));
      return NULL;
    }

  sshkey.size = strlen (sshprivkeystr);
  sshkey.data = g_try_malloc (sshkey.size + 1);
  if (!sshkey.data)
    {
      fprintf (stderr, "malloc failed in %s\n", __FUNCTION__);
      gnutls_x509_privkey_deinit (key);
      return NULL;
    }
  strcpy ((char*)sshkey.data, sshprivkeystr);

  rc = gnutls_x509_privkey_import_pkcs8 (key, &sshkey, GNUTLS_X509_FMT_PEM,
                                         passphrase, 0);
  g_free (sshkey.data);
  if (rc)
    {
      fprintf (stderr, "gnutls import pkcs#8 failed: %s\n",
               gnutls_strerror (rc));
      gnutls_x509_privkey_deinit (key);
      return NULL;
    }

  rc = gnutls_x509_privkey_export_rsa_raw2 (key, &m, &e, &d, &p, &q, &u,
                                            &dmp1, &dmq1);
  gnutls_x509_privkey_deinit (key);
  if (rc)
    {
      fprintf (stderr, "gnutls privkey export raw RSA key failed: %s\n",
               gnutls_strerror (rc));
      return NULL;
    }

  /* Create a DER object.  */
  init_membuf (&dermb, 4096);
  add_tlv (&dermb, 0x02, "", 1);                /* INTEGER: 0 */
  add_tlv (&dermb, 0x02, m.data, m.size);       /* INTEGER: m */
  add_tlv (&dermb, 0x02, e.data, e.size);       /* INTEGER: e */
  add_tlv (&dermb, 0x02, d.data, d.size);       /* INTEGER: d */
  add_tlv (&dermb, 0x02, q.data, q.size);       /* INTEGER: q */
  add_tlv (&dermb, 0x02, p.data, p.size);       /* INTEGER: p */
  add_tlv (&dermb, 0x02, dmq1.data, dmq1.size); /* INTEGER: dmq1 */
  add_tlv (&dermb, 0x02, dmp1.data, dmp1.size); /* INTEGER: dmp1 */
  add_tlv (&dermb, 0x02, u.data, u.size);       /* INTEGER: u */

  gnutls_free (m.data);
  gnutls_free (e.data);
  gnutls_free (d.data);
  gnutls_free (p.data);
  gnutls_free (q.data);
  gnutls_free (dmp1.data);
  gnutls_free (dmq1.data);
  gnutls_free (u.data);

  derbuf = get_membuf (&dermb, &derlen);
  if (!derbuf)
    {
      fprintf (stderr, "get_membuf failed in %s: %s\n",
               __FUNCTION__, strerror (-1));
      return NULL;
    }
  init_membuf (&dermb, 4096);
  add_tlv (&dermb, 0x30, derbuf, derlen);
  efree (&derbuf);
  derbuf = get_membuf (&dermb, &derlen);
  if (!derbuf)
    {
      fprintf (stderr, "get_membuf failed in %s (2): %s\n",
               __FUNCTION__, strerror (-1));
      return NULL;
    }

  der.data = derbuf;
  der.size = derlen;
  rc = gnutls_pem_base64_encode_alloc ("RSA PRIVATE KEY", &der, &pem);
  efree (&derbuf);
  if (rc)
    {
      fprintf (stderr, "gnutls_pem_base64_encode_alloc failed: %s\n",
               gnutls_strerror (rc));
      return NULL;
    }
  return (char*)pem.data;
}


/* Remove the temporary directory and its key file.  FILENAME is also freed. */
static void
remove_and_free_temp_key_file (char *filename)
{
  char *p;

  if (g_remove (filename) && errno != ENOENT)
    fprintf (stderr, "Failed to remove temporary file '%s': %s\n",
             filename, strerror (errno));
  p = strrchr (filename, '/');
  g_assert (p);
  *p = 0;
  if (g_rmdir (filename))
    fprintf (stderr, "Failed to remove temporary directory '%s': %s\n",
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
  if (
#if GLIB_CHECK_VERSION (2,30,0)
      !g_mkdtemp_full (key_dir, S_IRUSR|S_IWUSR|S_IXUSR)
#else
      !mkdtemp (key_dir)
#endif
      )
    {
      fprintf (stderr, "%s: g_mkdtemp_full/mkdtemp failed\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }

  privkey_filename = g_strdup_printf ("%s/key", key_dir);

 read_again:
  error = NULL;
  g_file_set_contents (privkey_filename, b64_key, strlen (b64_key), &error);
  if (error)
    {
      fprintf (stderr, "Failed to write private key to temporary file: %s\n",
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
  if (!ssh_privkey)
    fprintf (stderr, "Reading private key from '%s' failed: %s\n",
             privkey_filename, ssh_get_error (session));
  if (!ssh_privkey && !pkcs8_buffer)
    {
      fprintf (stderr, "Converting from PKCS#8 and trying again ...\n");

      pkcs8_buffer = pkcs8_to_sshprivatekey (b64_key, passphrase);
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
      fprintf (stderr, "... this worked.\n");
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
      fprintf (stderr, "%s: malloc failed\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }
  pkey->privkey = ssh_privkey;
  pkey->type = ssh_privatekey_type (ssh_privkey);
  if (pkey->type == SSH_KEYTYPE_UNKNOWN)
    {
      my_ssh_key_free (pkey);
      fprintf (stderr, "%s: key type is not known\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }

  /* Extract the public key from the private key.  */
  ssh_pubkey = publickey_from_privatekey (ssh_privkey);
  if (!ssh_pubkey)
    {
      my_ssh_key_free (pkey);
      fprintf (stderr, "%s: publickey_from_privatekey failed\n", __FUNCTION__);
      return SSH_AUTH_ERROR;
    }
  pkey->pubkey_string = publickey_to_string (ssh_pubkey);
  publickey_free (ssh_pubkey);
  if (!pkey->pubkey_string)
    {
      my_ssh_key_free (pkey);
      fprintf (stderr, "%s: publickey_to_string failed\n", __FUNCTION__);
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



/* Return the next session id.  Note that the first session ID we will
   hand out is an arbitrary high number, this is only to help
   debugging.  */
static int
next_session_id (void)
{
  static int last = 9000;
  int i;

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
  struct arglist *prefs;
  void *value;
  int type;
  unsigned short port;

  prefs = arg_get_value (lexic->script_infos, "preferences");
  if (prefs)
    {
      value = arg_get_value (prefs, "auth_port_ssh");
      if (value && (port = (unsigned short)strtoul (value, NULL, 10)) > 0)
        return port;
    }

  value = plug_get_key (lexic->script_infos, "Services/ssh", &type);
  if (value && type == KB_TYPE_INT && (port = GPOINTER_TO_SIZE (value)) > 0)
    return (unsigned short)port;

  return 22;
}


/**
 * @brief Connect to the target host via TCP and setup an ssh
 *        connection.
 *
 * If the named argument "socket" is given, that socket will be used
 * instead of a creating a new TCP connection.  If socket is not given
 * or 0, the port is looked up in the prefwerences and the KB unless
 * overriden by the named parameter "port".
 *
 * On success an ssh session to the host has been established; the
 * caller may then run an authentication function.  If the connection
 * is no longer needed, ssh_disconnect may be used to disconnect and
 * close the socket.
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
  const char *hostname;
  int port, sock;
  int tbl_slot;
  const char *s;
  int any_debug = 0;

  sock = get_int_local_var_by_name (lexic, "socket", 0);
  if (sock)
    port = 0; /* The port is ignored if "socket" is given.  */
   else
     {
       port = get_int_local_var_by_name (lexic, "port", 0);
       if (port <= 0)
         port = get_ssh_port (lexic);
     }

  hostname = plug_get_hostname (lexic->script_infos);
  if (!hostname)
    {
      /* Note: We want the hostname even if we are working on an open
         socket.  libssh may use it for example to maintain its
         known_hosts file.  */
      fprintf (stderr, "No hostname available to ssh_connect\n");
      return NULL;
    }

  session = ssh_new ();
  if (!session)
    {
      fprintf (stderr, "Failed to allocate a new SSH session\n");
      return NULL;
    }

  if ((s = getenv ("OPENVAS_LIBSSH_DEBUG")))
    {
      any_debug = 1;
      if (*s)
        {
          int intval = atoi (s);

          ssh_options_set (session, SSH_OPTIONS_LOG_VERBOSITY, &intval);
        }
    }

  if (ssh_options_set (session, SSH_OPTIONS_HOST, hostname))
    {
      fprintf (stderr, "Failed to set SSH hostname '%s': %s\n",
               hostname, ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  if (port)
    {
      unsigned int my_port = port;

      if (ssh_options_set (session, SSH_OPTIONS_PORT, &my_port))
        {
          fprintf (stderr, "Failed to set SSH port for '%s' to %d: %s\n",
                   hostname, port, ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
    }
  if (sock)
    {
      socket_t my_fd = sock;

      if (ssh_options_set (session, SSH_OPTIONS_FD, &my_fd))
        {
          fprintf (stderr, "Failed to set SSH fd for '%s' to %d: %s\n",
                   hostname, sock, ssh_get_error (session));
          ssh_free (session);
          return NULL;
        }
    }

  /* Find a place in the table to save the session.  */
  for (tbl_slot=0; tbl_slot < DIM (session_table); tbl_slot++)
    if (!session_table[tbl_slot].session_id)
      break;
  if (!(tbl_slot < DIM (session_table)))
    {
      fprintf (stderr, "No space left in SSH session table\n");
      ssh_free (session);
      return NULL;
    }

  /* Connect to the host.  */
  if (ssh_connect (session))
    {
      fprintf (stderr, "Failed to connect to SSH server '%s'"
               " (port %d, sock %d): %s\n",
               hostname, port, sock, ssh_get_error (session));
      ssh_free (session);
      /* return 0 to indicate the error.  */
      /* FIXME: Set the last error string.  */
      retc = alloc_typed_cell (CONST_INT);
      retc->x.i_val = 0;
      return retc;
    }

  /* How that we are connected, save the session.  */
  session_table[tbl_slot].session_id = next_session_id ();
  session_table[tbl_slot].session = session;
  session_table[tbl_slot].sock = ssh_get_fd (session);
  session_table[tbl_slot].user_set = 0;
  session_table[tbl_slot].verbose = any_debug;

  /* Return the session id.  */
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = session_table[tbl_slot].session_id;
  return retc;
}


/* Helper function to find and validate the session id.  On error 0 is
   returned, on success the session id and in this case the slot number
   from the table is stored at R_SLOT.  */
static int
find_session_id (lex_ctxt *lexic, const char *funcname, int *r_slot)
{
  int tbl_slot;
  int session_id;

  session_id = get_int_var_by_num (lexic, 0, -1);
  if (session_id <= 0)
    {
      if (funcname)
        fprintf (stderr, "Invalid SSH session id %d passed to %s\n",
                 session_id, funcname);
      return 0;
    }
  for (tbl_slot=0; tbl_slot < DIM (session_table); tbl_slot++)
    if (session_table[tbl_slot].session_id == session_id)
      break;
  if (!(tbl_slot < DIM (session_table)))
    {
      if (funcname)
        fprintf (stderr, "Bad SSH session id %d passed to %s\n",
                 session_id, funcname);
      return 0;
    }

  *r_slot = tbl_slot;
  return session_id;
}


/**
 * @brief Disconnect an ssh connection
 *
 * This function takes the ssh session id (as returned by ssh_connect)
 * as its only unnamed argument.  Passing 0 as session id is
 * explicitly allowed and does nothing.  If there are any open
 * channels they are closed as well and their ids will be marked as
 * invalid.
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

  session_id = find_session_id (lexic, NULL, &tbl_slot);
  if (!session_id)
    return FAKE_CELL;

  ssh_disconnect (session_table[tbl_slot].session);
  ssh_free (session_table[tbl_slot].session);
  session_table[tbl_slot].session_id = 0;
  session_table[tbl_slot].session = NULL;
  session_table[tbl_slot].sock = -1;
  return FAKE_CELL;
}


/**
 * @brief Given a socket, return the corresponding session id.
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
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The socket or -1 on error.
 */
tree_cell *
nasl_ssh_get_sock (lex_ctxt *lexic)
{
  int tbl_slot, sock;
  tree_cell *retc;

  if (!find_session_id (lexic, "ssh_get_sock", &tbl_slot))
    sock = -1;
  else
    sock = session_table[tbl_slot].sock;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = sock;
  return retc;
}



/**
 * @brief Authenticate a user on an ssh connection
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
  struct kb_item **kb;
  int retc_val = -1;
  int methods;
  int verbose;

  session_id = find_session_id (lexic, "ssh_userauth", &tbl_slot);
  if (!session_id)
    return NULL;  /* Ooops.  */
  session = session_table[tbl_slot].session;
  verbose = session_table[tbl_slot].verbose;


  /* Check if we need to set the user.  This is done only once per
     session.  */
  if (!session_table[tbl_slot].user_set)
    {
      char *username;

      username = get_str_local_var_by_name (lexic, "login");
      if (!username)
        {
          kb = plug_get_kb (lexic->script_infos);
          username = kb_item_get_str (kb, "Secret/SSH/login");
        }
      if (username && ssh_options_set (session, SSH_OPTIONS_USER, username))
        {
          fprintf (stderr, "Failed to set SSH username '%s': %s\n",
                   username, ssh_get_error (session));
          return NULL; /* Ooops.  */
        }
      /* In any case mark the user has set.  */
      session_table[tbl_slot].user_set = 1;
    }

  /* First check whether any specific methods have been requested.  If
     not fall back to the default.  */
  if ((password = get_str_local_var_by_name (lexic, "password")))
    ; /* Password provided - do not bother looking for a private key.  */
  else if ((privkeystr = get_str_local_var_by_name (lexic, "privatekey")))
    ; /* A private key is available.  */
  else
    {
      /* Nothing supported.  Use the values from the KB.  */
      kb = plug_get_kb (lexic->script_infos);
      password      = kb_item_get_str (kb, "Secret/SSH/password");
      privkeystr    = kb_item_get_str (kb, "Secret/SSH/privatekey");
    }

  /* If a private key is available get a corresponding passphrase so
     that we are later able to unprotect that key if needed.  */
  if (privkeystr)
    {
      privkeypass = get_str_local_var_by_name (lexic, "passphrase");
      if (!privkeypass)
        {
          kb = plug_get_kb (lexic->script_infos);
          privkeypass = kb_item_get_str (kb, "Secret/SSH/passphrase");
        }
    }

  /* Get the list of supported authentication schemes.  */
  rc = ssh_userauth_none (session, NULL);
  if (rc == SSH_AUTH_SUCCESS)
    {
      fprintf (stderr,
               "SSH authentication succeeded using the none method - "
               "should not happen; very old server?\n");
      retc_val = 0;
      goto leave;
    }
  else if (rc == SSH_AUTH_DENIED)
    {
      methods = ssh_userauth_list (session, NULL);
    }
  else
    {
      fprintf (stderr,
               "SSH server did not return a list of authentication methods - "
               "trying all\n");
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

      fprintf (stderr,
               "SSH password authentication failed for session %d: %s\n",
               session_id, ssh_get_error (session));
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
                fprintf (stderr, "SSH kbdint name='%s'\n", s);
              s = ssh_userauth_kbdint_getinstruction (session);
              if (s && *s)
                fprintf (stderr, "SSH kbdint instruction='%s'\n", s);
            }
          nprompt = ssh_userauth_kbdint_getnprompts (session);
          for (n=0; n < nprompt; n++)
            {
              s = ssh_userauth_kbdint_getprompt (session, n, &echoflag);
              if (s && *s && verbose)
                fprintf (stderr, "SSH kbdint prompt='%s'%s\n",
                         s, echoflag? "":" [hide input]");
              if (s && *s && !echoflag && !found_prompt)
                {
                  found_prompt = 1;
                  rc = ssh_userauth_kbdint_setanswer (session, n, password);
                  if (rc != SSH_AUTH_SUCCESS)
                    {
                      fprintf (stderr,
                               "SSH keyboard-interactive authentication failed"
                               " at prompt %d for session %d: %s\n",
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

      fprintf (stderr,
               "SSH keyboard-interactive authentication failed for session %d"
               ": %s\n",
               session_id, ssh_get_error (session));
      /* Keep on trying.  */
    }

  /* If we have a private key, try public key authentication.  */
  if (privkeystr && (methods & SSH_AUTH_METHOD_PUBLICKEY))
    {
      my_ssh_key key = NULL;

      /* SESSION is only used by our emulation - FIXME: remove it for 0.6.  */
      if (my_ssh_pki_import_privkey_base64 (session, privkeystr, privkeypass,
                                            NULL, NULL, &key))
        {
          fprintf (stderr,
                   "SSH public key authentication failed for session %d: %s\n",
                   session_id, "Error converting provided key");
        }
      else if (my_ssh_userauth_try_publickey (session, NULL, key)
               != SSH_AUTH_SUCCESS)
        {
          fprintf (stderr,
                   "SSH public key authentication failed for session %d: %s\n",
                   session_id, "Server does not want our key");
        }
      else if (my_ssh_userauth_publickey (session, NULL, key)
               == SSH_AUTH_SUCCESS)
        {
          retc_val = 0;
          my_ssh_key_free (key);
          goto leave;
        }
      my_ssh_key_free (key);
      /* Keep on trying.  */
    }

  fprintf (stderr, "SSH authentication failed for session %d: %s\n",
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
 * @brief Run a command via ssh.
 *
 * The function opens a channel, to the remote end, and ask it to
 * execite a command.  The output of the command is then returned as a
 * data block.  The first unnamed argument is the session id. The
 * command itself is expected as string in the named argument "cmd".
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
  char *cmd;
  ssh_channel channel;
  int rc;
  char buffer[1024];
  membuf_t response;
  int nread;
  size_t len;
  tree_cell *retc;
  char *p;

  session_id = find_session_id (lexic, "ssh_request_exec", &tbl_slot);
  if (!session_id)
    return NULL;
  session = session_table[tbl_slot].session;

  cmd = get_str_local_var_by_name (lexic, "cmd");
  if (!cmd || !*cmd)
    {
      fprintf (stderr, "No command passed to ssh_request_exec\n");
      return NULL;
    }

  channel = ssh_channel_new (session);
  if (!channel)
    {
      fprintf (stderr, "ssh_channel_new failed: %s\n", ssh_get_error (session));
      return NULL;
    }

  rc = ssh_channel_open_session (channel);
  if (rc)
    {
      /* FIXME: Handle SSH_AGAIN.  */
      fprintf (stderr, "ssh_channel_open_session failed: %s\n",
               ssh_get_error (session));
      ssh_channel_send_eof (channel);
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      return NULL;
    }

  rc = ssh_channel_request_exec (channel, cmd);
  if (rc)
    {
      /* FIXME: Handle SSH_AGAIN.  */
      fprintf (stderr, "ssh_channel_request_exec failed for '%s': %s\n",
               cmd, ssh_get_error (session));
      ssh_channel_send_eof (channel);
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      return NULL;
    }

  /* Allocate some space in advance.  Most commands won't output too
     much and thus 512 bytes (6 standard terminal lines) should often
     be sufficient.  */
  init_membuf (&response, 512);
  while ((nread = ssh_channel_read (channel, buffer, sizeof buffer, 0)) > 0)
    {
      put_membuf (&response, buffer, nread);
    }

  if (nread < 0)
    {
      fprintf (stderr, "ssh_channel_read failed for session id %d: %s\n",
               session_id, ssh_get_error (session));
      ssh_channel_send_eof (channel);
      p = get_membuf (&response, NULL);
      efree (&p);
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      return NULL;
    }

  ssh_channel_send_eof (channel);
  ssh_channel_close (channel);
  ssh_channel_free (channel);

  p = get_membuf (&response, &len);
  if (!p)
    {
      fprintf (stderr, "ssh_request_exec memory problem: %s\n",
               strerror (-1));
      return NULL;
    }

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = p;
  return retc;
}



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
               "Insufficient parameters: port=%d, username=%s, commandline=%s\n",
               port, username, commandline);
      return NULL;
    }
  if ((privkey == NULL) && (password == NULL))
    {
      fprintf (stderr,
               "Insufficient parameters: Both privkey and password are NULL\n");
      return NULL;
    }

  hostname = plug_get_hostname (script_infos);

  session = ssh_new ();
  if (!session)
    {
      fprintf (stderr, "Failed to allocate a new SSH session\n");
      return NULL;
    }

  ssh_options_set (session, SSH_OPTIONS_HOST, hostname);
  ssh_options_set (session, SSH_OPTIONS_USER, username);
  ssh_options_set (session, SSH_OPTIONS_PORT, &port);

  ssh_connect (session);
  if (session == NULL)
    {
      fprintf (stderr, "Failed to connect to SSH server '%s': %s\n",
               hostname, ssh_get_error (session));
      ssh_free (session);
      return NULL;
    }

  if (strlen (password) != 0)
    {
      /* We could authenticate via password */
      rc = ssh_userauth_password (session, NULL, password);
      if (rc != SSH_AUTH_SUCCESS)
        {
          fprintf (stderr,
                   "SSH password authentication to '%s%s%s' failed: %s\n",
                   username?username:"",
                   username?"@":"",
                   hostname, ssh_get_error (session));
          ssh_disconnect (session);
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
          g_free (pubkey_filename);
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
      fprintf (stderr, "ssh_channel_new failed: %s\n", ssh_get_error (session));
      ssh_disconnect (session);
      ssh_free (session);
      return NULL;
    }

  rc = ssh_channel_open_session (channel);
  if (rc < 0)
    {
      fprintf (stderr, "ssh_channel_open_session failed: %s\n",
               ssh_get_error (session));
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
      fprintf (stderr, "ssh_channel_request_exec failed: %s\n",
               ssh_get_error (session));
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
      fprintf (stderr, "ssh_channel_read failed: %s\n",
               ssh_get_error (session));
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

#endif /*HAVE_LIBSSH*/
