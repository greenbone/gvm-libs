/* OpenVAS
 * $Id$
 * Description: Network Functions.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 * Michel Arboi (Original pre-fork development)
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2002 Renaud Deraison
 *               SSL Support Copyright (C) 2001 Michel Arboi
 * Copyright (C) 2012 Greenbone Networks GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>              /* for FILE */
#include <sys/time.h>           /* for gettimeofday */

#include <glib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "network.h"            /* for socket_close() */
#include "../base/kb.h"         /* for kb_item_get_str() */

#include "ids_send.h"
#include "prefs.h"
#include "plugutils.h"
#include "internal_com.h" /* for INTERNAL_COMM_MSG_TYPE_CTRL */
#include "support.h"
#include "openvas_logging.h"
#include "openvas_server.h"

#define TIMEOUT 20

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

/*----------------------------------------------------------------*
 * Low-level connection management                                *
 *----------------------------------------------------------------*/

/** OpenVAS "FILE" structure */
typedef struct
{
  int fd;        /**< socket number, or whatever */
  /*
   * "transport" layer code when stream is encapsultated. Negative transport
   * signals a free descriptor.
   */
  openvas_encaps_t transport;
  char *priority;/**< Malloced "priority" string for certain transports.  */
  int timeout;   /**< timeout, in seconds. Special values: -2 for default */
  int options;   /**< Misc options - see ids_send.h */

  int port;

  gnutls_session_t tls_session;              /**< GnuTLS session */
  gnutls_certificate_credentials_t tls_cred; /**< GnuTLS credentials */

  pid_t pid;    /**< Owner - for debugging only */

  char *buf;    /**< NULL if unbuffered */
  int bufsz, bufcnt, bufptr;
  int last_err;
} openvas_connection;

/**
 * The role of this offset is:
 * 1. To detect bugs when the program tries to write to a bad fd
 * 2. See if a fd is a real socket or a "openvas descriptor". This is a
 * quick & dirty hack and should be changed!!!
 */
#define OPENVAS_FD_MAX 1024
#define OPENVAS_FD_OFF 1000000

static openvas_connection connections[OPENVAS_FD_MAX];

/**
 * @brief Object to store a list of hooks for close_stream_connection.
 */
struct csc_hook_s
{
  struct csc_hook_s *next;
  int (*fnc)(int fd);
};

/**
 * @brief Linked list of hooks to be run by close_stream_connection.
 */
static struct csc_hook_s *csc_hooks;


/**
 * OPENVAS_STREAM(x) is TRUE if \<x\> is a OpenVAS-ified fd
 */
#define OPENVAS_STREAM(x) (((x - OPENVAS_FD_OFF) < OPENVAS_FD_MAX) && ((x - OPENVAS_FD_OFF) >=0))

/**
 * determine the openvas_connection* from the openvas fd
 */
#define OVAS_CONNECTION_FROM_FD(fd) (connections + ((fd) - OPENVAS_FD_OFF))

static void
renice_myself (void)
{
  static pid_t pid = 0;
  pid_t cpid = getpid ();

  if (pid != cpid)
    {
      int renice_result;
      if (nice (0) >= 10)
        return;
      pid = cpid;
      errno = 0;
      renice_result = nice (1);
      if (renice_result == -1 && errno != 0)
        {
          log_legacy_write ("Unable to renice process: %d", errno);
        }
    }
}

/**
 * Same as perror(), but prefixes the data by our pid.
 */
static int
pid_perror (const char *error)
{
  log_legacy_write ("[%d] %s : %s\n", getpid (), error, strerror (errno));
  return 0;
}

int
stream_get_err (int fd)
{
  openvas_connection *p;

  if (!OPENVAS_STREAM (fd))
    {
      errno = EINVAL;
      return -1;
    }

  p = OVAS_CONNECTION_FROM_FD (fd);
  return p->last_err;
}

/**
 * @brief Returns a free file descriptor.
 */
static int
get_connection_fd (void)
{
  int i;

  for (i = 0; i < OPENVAS_FD_MAX; i++)
    {
      if (connections[i].pid == 0)        /* Not used */
        {
          bzero (&(connections[i]), sizeof (connections[i]));
          connections[i].pid = getpid ();
          return i + OPENVAS_FD_OFF;
        }
    }
  log_legacy_write ("[%d] %s:%d : Out of OpenVAS file descriptors\n",
                    getpid (), __FILE__, __LINE__);
  errno = EMFILE;
  return -1;
}



static int
release_connection_fd (int fd, int already_closed)
{
  openvas_connection *p;

  if (!OPENVAS_STREAM (fd))
    {
      errno = EINVAL;
      return -1;
    }
  p = OVAS_CONNECTION_FROM_FD (fd);

  g_free (p->buf);
  p->buf = 0;

  /* TLS FIXME: we should call gnutls_bye somewhere.  OTOH, the OpenSSL
   * equivalent SSL_shutdown wasn't called anywhere in the OpenVAS
   * (libopenvas nor elsewhere) code either.
   */

/* So far, fd is always a socket. If this is changed in the future, this
 * code shall be fixed. */
  if (p->fd >= 0)
    {
#if DEBUG_SSL > 1
      log_legacy_write (
               "[%d] release_connection_fd: fd > 0 fd=%d\n", getpid (), p->fd);
#endif
      if (shutdown (p->fd, 2) < 0)
        {
#if DEBUG_SSL > 1
          /*
           * It's not uncommon to see that one fail, since a lot of
           * services close the connection before we ask them to
           * (ie: http), so we don't show this error by default
           */
          pid_perror ("release_connection_fd: shutdown()");
#endif
        }
      if (!already_closed && socket_close (p->fd) < 0)
        pid_perror ("release_connection_fd: close()");
    }

  if (p->tls_session != NULL)
    gnutls_deinit (p->tls_session);
  if (p->tls_cred != NULL)
    gnutls_certificate_free_credentials (p->tls_cred);

  g_free (p->priority);
  p->priority = NULL;

  bzero (p, sizeof (*p));
  p->transport = -1;
  p->pid = 0;

  return 0;
}

/* ******** Compatibility function ******** */

/** @todo TLS FIXME: migrate this to TLS */
/** @todo Fix the voidness of the ssl parameter (problematic in 64bit env.)
  *       here or on caller-side */
/**
 * @param soc Socket to use.
 */
int
openvas_register_connection (int soc, void *ssl,
                             gnutls_certificate_credentials_t certcred,
                             openvas_encaps_t encaps)
{
  int fd;
  openvas_connection *p;

  if ((fd = get_connection_fd ()) < 0)
    return -1;
  p = OVAS_CONNECTION_FROM_FD (fd);

  p->tls_session = ssl;
  p->tls_cred = certcred;

  p->timeout = TIMEOUT;         /* default value */
  p->port = 0;                  /* just used for debug */
  p->fd = soc;
  p->transport = encaps;
  p->priority = NULL;
  p->last_err = 0;

  return fd;
}

int
openvas_deregister_connection (int fd)
{
  openvas_connection *p;
  if (!OPENVAS_STREAM (fd))
    {
      errno = EINVAL;
      return -1;
    }

  p = connections + (fd - OPENVAS_FD_OFF);
  /* Fixme: Code duplicated from release_connection_fd.  Check usage
     of this function make sure that TLS stuff is also released in
     case it is used here.  */
  g_free (p->priority);
  p->priority = NULL;
  bzero (p, sizeof (*p));
  p->transport = -1;
  return 0;
}

/*----------------------------------------------------------------*
 * High-level connection management                               *
 *----------------------------------------------------------------*/

static int __port_closed;

static int
unblock_socket (int soc)
{
  int flags = fcntl (soc, F_GETFL, 0);
  if (flags < 0)
    {
      pid_perror ("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl (soc, F_SETFL, O_NONBLOCK | flags) < 0)
    {
      pid_perror ("fcntl(F_SETFL,O_NONBLOCK)");
      return -1;
    }
  return 0;
}

static int
block_socket (int soc)
{
  int flags = fcntl (soc, F_GETFL, 0);
  if (flags < 0)
    {
      pid_perror ("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl (soc, F_SETFL, (~O_NONBLOCK) & flags) < 0)
    {
      pid_perror ("fcntl(F_SETFL,~O_NONBLOCK)");
      return -1;
    }
  return 0;
}

/*
 * Initialize the SSL library (error strings and algorithms) and try
 * to set the pseudo random generator to something less silly than the
 * default value: 1 according to SVID 3, BSD 4.3, ISO 9899 :-(
 */

void
tlserror (char *txt, int err)
{
  log_legacy_write ("[%d] %s: %s\n", getpid (), txt, gnutls_strerror (err));
}

#ifdef DEBUG_SSL
static void
log_message_gnutls (int level, const char *msg)
{
  log_legacy_write ("LEVEL %d: %s\n", level, msg);
}
#endif

/**
 * @brief Initializes SSL support.
 */
int
openvas_SSL_init ()
{
#ifdef DEBUG_SSL
  gnutls_global_set_log_level (2);
  gnutls_global_set_log_function (log_message_gnutls);
#endif

  int ret = gnutls_global_init ();
  if (ret < 0)
    {
      tlserror ("gnutls_global_init", ret);
      return -1;
    }

  return 0;
}


int
openvas_get_socket_from_connection (int fd)
{
  openvas_connection *fp;

  if (!OPENVAS_STREAM (fd))
    {
      log_legacy_write (
               "[%d] openvas_get_socket_from_connection: bad fd <%d>\n",
               getpid (), fd);
      log_legacy_fflush ();
      return fd;
    }
  fp = connections + (fd - OPENVAS_FD_OFF);
  if (fp->transport <= 0)
    {
      log_legacy_write (
               "openvas_get_socket_from_connection: fd <%d> is closed\n", fd);
      return -1;
    }
  return fp->fd;
}

gnutls_session_t
ovas_get_tlssession_from_connection (int fd)
{
  openvas_connection *fp;

  if (!OPENVAS_STREAM (fd))
    return NULL;

  fp = connections + (fd - OPENVAS_FD_OFF);
  return fp->tls_session;
}

/**
 * Sets the priorities for the GnuTLS session according to encaps.
 * PRIORITY is used to convey custom priorities; it is only used if ENCAPS is
 * set to OPENVAS_ENCAPS_TLScustom.
 */
static int
set_gnutls_protocol (gnutls_session_t session, openvas_encaps_t encaps,
                     const char *priority)
{
  const char * priorities;
  const char * errloc;
  int err;

  switch (encaps)
    {
      case OPENVAS_ENCAPS_SSLv3:
        priorities = "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0:+ARCFOUR-128:%COMPAT";
        break;
      case OPENVAS_ENCAPS_TLSv1:
        priorities = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+ARCFOUR-128:%COMPAT";
        break;
      case OPENVAS_ENCAPS_TLSv11:
        priorities = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.1:+ARCFOUR-128:%COMPAT";
        break;
      case OPENVAS_ENCAPS_TLSv12:
        priorities = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:+ARCFOUR-128:%COMPAT";
        break;
      case OPENVAS_ENCAPS_SSLv23:        /* Compatibility mode */
        priorities = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-SSL3.0:+ARCFOUR-128:%COMPAT";
        break;
      default:
#if DEBUG_SSL > 0
        log_legacy_write ("*Bug* at %s:%d. Unknown transport %d\n", __FILE__,
                          __LINE__, encaps);
#endif
      case OPENVAS_ENCAPS_TLScustom:
        priorities = priority;
        break;
    }

  if ((err = gnutls_priority_set_direct (session, priorities, &errloc)))
    {
      log_legacy_write ("[%d] setting session priorities '%.20s': %s\n",
                        getpid (), errloc, gnutls_strerror (err));
      return -1;
    }

  return 0;
}

/**
 * @brief Loads a certificate and the corresponding private key from PEM files.
 *
 * The private key may be encrypted, in which case the password to
 * decrypt the key should be given as the passwd parameter.
 *
 * @return Returns 0 on success and -1 on failure.
 */
static int
load_cert_and_key (gnutls_certificate_credentials_t xcred, const char *cert,
                   const char *key, const char *passwd)
{
  gnutls_x509_crt_t x509_crt = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_datum_t data;
  int ret;
  int result = 0;

  if (load_gnutls_file (cert, &data))
    {
      log_legacy_write ("[%d] load_cert_and_key: Error loading cert file %s\n",
                        getpid (), cert);
      result = -1;
      goto cleanup;
    }
  ret = gnutls_x509_crt_init (&x509_crt);
  if (ret < 0)
    {
      tlserror ("gnutls_x509_crt_init", ret);
      /* x509_crt may be != NULL even if gnutls_x509_crt_init fails */
      x509_crt = NULL;
      result = -1;
      goto cleanup;
    }
  ret = gnutls_x509_crt_import (x509_crt, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      tlserror ("gnutls_x509_crt_import", ret);
      result = -1;
      goto cleanup;
    }
  unload_gnutls_file (&data);

  if (load_gnutls_file (key, &data))
    {
      log_legacy_write ("[%d] load_cert_and_key: Error loading key file %s\n",
                        getpid (), key);
      result = -1;
      goto cleanup;
    }
  ret = gnutls_x509_privkey_init (&x509_key);
  if (ret < 0)
    {
      tlserror ("gnutls_x509_privkey_init", ret);
      /* x509_key may be != NULL even if gnutls_x509_privkey_init fails */
      x509_key = NULL;
      result = -1;
      goto cleanup;
    }
  if (passwd)
    {
      ret =
        gnutls_x509_privkey_import_pkcs8 (x509_key, &data, GNUTLS_X509_FMT_PEM,
                                          passwd, 0);
      if (ret < 0)
        {
          tlserror ("gnutls_x509_privkey_import_pkcs8", ret);
          result = -1;
          goto cleanup;
        }
    }
  else
    {
      ret = gnutls_x509_privkey_import (x509_key, &data, GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          tlserror ("gnutls_x509_privkey_import", ret);
          result = -1;
          goto cleanup;
        }
    }
  unload_gnutls_file (&data);

  ret = gnutls_certificate_set_x509_key (xcred, &x509_crt, 1, x509_key);
  if (ret < 0)
    {
      tlserror ("gnutls_certificate_set_x509_key", ret);
      result = -1;
      goto cleanup;
    }

cleanup:

  if (x509_crt)
    gnutls_x509_crt_deinit (x509_crt);
  if (x509_key)
    gnutls_x509_privkey_deinit (x509_key);

  return result;
}

static int
is_ip_address (const char *str)
{
  struct sockaddr_in sa;
  struct sockaddr_in6 sa6;

  if (inet_pton (AF_INET, str, &(sa.sin_addr)) == 1)
    return 1;

  return inet_pton (AF_INET6, str, &(sa6.sin6_addr)) == 1;
}

static int
open_SSL_connection (openvas_connection * fp, const char *cert,
                     const char *key, const char *passwd, const char *cafile,
                     const char *hostname)
{
  int ret, err, d;
  time_t tictac;
  fd_set fdw, fdr;
  struct timeval to;

  ret = gnutls_init (&(fp->tls_session), GNUTLS_CLIENT);
  if (ret < 0)
    {
      tlserror ("gnutls_init", ret);
      return -1;
    }

  /* set_gnutls_protocol handles OPENVAS_ENCAPS_SSLv2 by falling back
   * to OPENVAS_ENCAPS_SSLv23.  However, this function
   * (open_SSL_connection) is called only by open_stream_connection and
   * open_stream_connection will exit with an error code if called with
   * OPENVAS_ENCAPS_SSLv2, so it should never end up calling
   * open_SSL_connection with OPENVAS_ENCAPS_SSLv2.
   */
  if (set_gnutls_protocol (fp->tls_session, fp->transport, fp->priority) < 0)
    return -1;

  if (hostname && !is_ip_address (hostname))
    gnutls_server_name_set (fp->tls_session, GNUTLS_NAME_DNS, hostname,
                            strlen (hostname));

  ret = gnutls_certificate_allocate_credentials (&(fp->tls_cred));
  if (ret < 0)
    {
      tlserror ("gnutls_certificate_allocate_credentials", ret);
      return -1;
    }
  ret =
    gnutls_credentials_set (fp->tls_session, GNUTLS_CRD_CERTIFICATE,
                            fp->tls_cred);
  if (ret < 0)
    {
      tlserror ("gnutls_credentials_set", ret);
      return -1;
    }

  if (cert != NULL && key != NULL)
    {
      if (load_cert_and_key (fp->tls_cred, cert, key, passwd) < 0)
        return -1;
    }

  if (cafile != NULL)
    {
      ret =
        gnutls_certificate_set_x509_trust_file (fp->tls_cred, cafile,
                                                GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          tlserror ("gnutls_certificate_set_x509_trust_file", ret);
          return -1;
        }
    }

  unblock_socket (fp->fd);

  gnutls_transport_set_ptr (fp->tls_session,
                            (gnutls_transport_ptr_t) GSIZE_TO_POINTER (fp->fd));

  tictac = time (NULL);

  for (;;)
    {
      err = gnutls_handshake (fp->tls_session);

      if (err == 0)
        return 1;

      if (err != GNUTLS_E_INTERRUPTED && err != GNUTLS_E_AGAIN
          && err != GNUTLS_E_WARNING_ALERT_RECEIVED)
        {
#ifdef DEBUG_SSL
          tlserror ("gnutls_handshake", err);
#endif
          return -1;
        }

      FD_ZERO (&fdr);
      FD_SET (fp->fd, &fdr);
      FD_ZERO (&fdw);
      FD_SET (fp->fd, &fdw);

      do
        {
          d = tictac + fp->timeout - time (NULL);
          if (d <= 0)
            {
              fp->last_err = ETIMEDOUT;
              return -1;
            }
          to.tv_sec = d;
          to.tv_usec = 0;
          errno = 0;
          if ((ret = select (fp->fd + 1, &fdr, &fdw, NULL, &to)) <= 0)
            {
#if DEBUG_SSL > 1
              pid_perror ("select");
#endif
            }
        }
      while (ret < 0 && errno == EINTR);

      if (ret <= 0)
        {
          fp->last_err = ETIMEDOUT;
          return -1;
        }
    }
 /*NOTREACHED*/}


static void
set_ids_evasion_mode (struct arglist *args, openvas_connection * fp)
{
  kb_t kb = plug_get_kb (args);
  char *ids_evasion_split, *ids_evasion_inject, *ids_evasion_short_ttl;
  char *ids_evasion_fake_rst;
  int option = 0;

  if (kb_item_get_int (kb, "NIDS/TCP/enabled") != 1)
    return;

  ids_evasion_split = kb_item_get_str (kb, "NIDS/TCP/split");
  ids_evasion_inject = kb_item_get_str (kb, "NIDS/TCP/inject");
  ids_evasion_short_ttl = kb_item_get_str (kb, "NIDS/TCP/short_ttl");
  ids_evasion_fake_rst = kb_item_get_str (kb, "NIDS/TCP/fake_rst");
  /*
   * These first three options are mutually exclusive
   */
  if (ids_evasion_split != NULL && strcmp (ids_evasion_split, "yes") == 0)
    option = OPENVAS_CNX_IDS_EVASION_SPLIT;

  if (ids_evasion_inject != NULL && strcmp (ids_evasion_inject, "yes") == 0)
    option = OPENVAS_CNX_IDS_EVASION_INJECT;

  if (ids_evasion_short_ttl != NULL
      && strcmp (ids_evasion_short_ttl, "yes") == 0)
    option = OPENVAS_CNX_IDS_EVASION_SHORT_TTL;


  /*
   * This is not exclusive with the above
   */
  if (ids_evasion_fake_rst != NULL && strcmp (ids_evasion_fake_rst, "yes") == 0)
    option |= OPENVAS_CNX_IDS_EVASION_FAKE_RST;

  if (option)
    {
      int n = 1;
      (void) setsockopt (fp->fd, SOL_SOCKET, SO_SNDLOWAT, (void *) &n,
                         sizeof (n));
      fp->options |= option;
    }
  g_free (ids_evasion_split);
  g_free (ids_evasion_inject);
  g_free (ids_evasion_short_ttl);
  g_free (ids_evasion_fake_rst);
}

/*
 * @brief Upgrade an ENCAPS_IP socket to an SSL/TLS encapsulated one.
 *
 * @param[in]   fd          Socket file descriptor.
 * @param[in]   transport   Encapsulation type.
 * @param[in]   arg         Script args.
 *
 * @return -1 if error, socket file descriptor value otherwise.
 */
int
socket_negotiate_ssl (int fd, openvas_encaps_t transport, struct arglist *args)
{
  char *cert = NULL, *key = NULL, *passwd = NULL, *cafile = NULL;
  char *hostname = NULL;
  openvas_connection *fp;
  kb_t kb;
  char buf[1024];

  if (!fd_is_stream (fd))
    {
      log_legacy_write ("Socket %d is not stream\n", fd);
      return -1;
    }
  fp = OVAS_CONNECTION_FROM_FD(fd);
  kb = plug_get_kb (args);
  cert = kb_item_get_str (kb, "SSL/cert");
  key = kb_item_get_str (kb, "SSL/key");
  passwd = kb_item_get_str (kb, "SSL/password");
  cafile = kb_item_get_str (kb, "SSL/CA");
  snprintf (buf, sizeof (buf), "Host/SNI/%d/force_disable", fp->port);
  if (kb_item_get_int (kb, buf) <= 0)
    hostname = plug_get_host_fqdn (args);

  fp->transport = transport;
  fp->priority = NULL;
  if (open_SSL_connection (fp, cert, key, passwd, cafile, hostname) <= 0)
    {
      log_legacy_write ("socket_negotiate_ssl: SSL connection failed.\n");
      release_connection_fd (fd, 0);
      return -1;
    }
  return fd;
}

/*
 * @brief Get the peer's certificate from an SSL/TLS encapsulated connection.
 *
 * @param[in]   fd      Socket file descriptor.
 * @param[out]  cert    Memory pointer to fill cert pointer.
 * @param[out]  certlen Size of cert.
 */
void
socket_get_cert (int fd, void **cert, int *certlen)
{
  gnutls_session_t session;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_len = 0;

  if (!cert || !certlen)
    return;
  if (!fd_is_stream (fd))
    {
      log_legacy_write ("Socket %d is not stream\n", fd);
      return;
    }
  session = ovas_get_tlssession_from_connection (fd);
  if (!session)
    {
      log_legacy_write ("Socket %d is not SSL/TLS encapsulated\n", fd);
      return;
    }
  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    return;
  cert_list = gnutls_certificate_get_peers (session, &cert_list_len);
  if (cert_list_len == 0)
    return;
  *certlen = cert_list[0].size;
  *cert = g_memdup (cert_list[0].data, *certlen);
}

/*
 * @brief Get the TLS version of a connection.
 *
 * @param[in]   fd  Socket file descriptor.
 *
 * @return OPENVAS_ENCAPS value if valid session and success, -1 if error.
 */
int
socket_get_ssl_version (int fd)
{
  gnutls_session_t session;
  gnutls_protocol_t version;

  if (!fd_is_stream (fd))
    {
      log_legacy_write ("Socket %d is not stream\n", fd);
      return -1;
    }
  session = ovas_get_tlssession_from_connection (fd);
  if (!session)
    {
      log_legacy_write ("Socket %d is not SSL/TLS encapsulated\n", fd);
      return -1;
    }

  version = gnutls_protocol_get_version (session);
  switch (version)
    {
      case GNUTLS_SSL3:
        return OPENVAS_ENCAPS_SSLv3;
      case GNUTLS_TLS1:
        return OPENVAS_ENCAPS_TLSv1;
      case GNUTLS_TLS1_1:
        return OPENVAS_ENCAPS_TLSv11;
      case GNUTLS_TLS1_2:
        return OPENVAS_ENCAPS_TLSv12;
      default:
        return -1;
    }
}

/*
 * @brief Get the session ID from an SSL/TLS encapsulated connection.
 *
 * @param[in]   fd      Socket file descriptor.
 * @param[out]  sid     Pointer where to store Session ID pointer.
 * @param[out]  ssize   Size of session id buffer.
 */
void
socket_get_ssl_session_id (int fd, void **sid, size_t *ssize)
{
  gnutls_session_t session;
  void *tmp;
  *ssize = GNUTLS_MAX_SESSION_ID;
  int ret;

  if (!sid)
    return;
  if (!fd_is_stream (fd))
    {
      log_legacy_write ("Socket %d is not stream\n", fd);
      return;
    }
  session = ovas_get_tlssession_from_connection (fd);
  if (!session)
    {
      log_legacy_write ("Socket %d is not SSL/TLS encapsulated\n", fd);
      return;
    }
  tmp = g_malloc0 (*ssize);
  ret = gnutls_session_get_id (session, tmp, ssize);
  if (ret == GNUTLS_E_SUCCESS)
    *sid = tmp;
  else
    {
      g_free (tmp);
      *ssize = 0;
      tlserror ("gnutls_session_id", ret);
    }
}

/*
 * @brief Get the cipher suite used by a SSL/TLS connection.
 *
 * @param[in]   fd  Socket file descriptor.
 *
 * @return Cipher Suite ID, -1 if error.
 */
int
socket_get_ssl_ciphersuite (int fd)
{
  gnutls_session_t session;
  gnutls_kx_algorithm_t kx, kx2;
  gnutls_cipher_algorithm_t cipher, cipher2;
  gnutls_mac_algorithm_t mac, mac2;
  size_t idx = 0;
  unsigned char cs_id[2];

  if (!fd_is_stream (fd))
    {
      log_legacy_write ("Socket %d is not stream\n", fd);
      return -1;
    }
  session = ovas_get_tlssession_from_connection (fd);
  if (!session)
    {
      log_legacy_write ("Socket %d is not SSL/TLS encapsulated\n", fd);
      return -1;
    }

  kx = gnutls_kx_get (session);
  cipher = gnutls_cipher_get (session);
  mac = gnutls_mac_get (session);
  while (gnutls_cipher_suite_info (idx, (void *) cs_id, &kx2, &cipher2, &mac2,
                                   NULL))
    {
      if (kx == kx2 && cipher == cipher2 && mac == mac2)
        return cs_id[0] + cs_id[1];
      idx++;
    }
  return -1;
}

/* Extended version of open_stream_connection to allow passing a
   priority string.

   ABI_BREAK_NOTE: Merge this with open_stream_connection.  */
int
open_stream_connection_ext (struct arglist *args, unsigned int port,
                            int transport, int timeout, const char *priority)
{
  int fd;
  openvas_connection *fp;
  char *cert = NULL;
  char *key = NULL;
  char *passwd = NULL;
  char *cafile = NULL;
  char *hostname = NULL;

  if (!priority)
    priority = ""; /* To us an empty string is equivalent to NULL.  */

#if DEBUG_SSL > 2
  log_legacy_write (
           "[%d] open_stream_connection: TCP:%d transport:%d timeout:%d "
           " priority: '%s'\n",
           getpid (), port, transport, timeout, priority);
#endif

  if (timeout == -2)
    timeout = TIMEOUT;

  switch (transport)
    {
    case OPENVAS_ENCAPS_IP:

    case OPENVAS_ENCAPS_SSLv23:
    case OPENVAS_ENCAPS_SSLv3:
    case OPENVAS_ENCAPS_TLSv1:
    case OPENVAS_ENCAPS_TLSv11:
    case OPENVAS_ENCAPS_TLSv12:
    case OPENVAS_ENCAPS_TLScustom:
    case OPENVAS_ENCAPS_SSLv2:
      break;

    default:
      log_legacy_write ("open_stream_connection_ext(): unsupported transport"
                        " layer %d\n", transport);
      errno = EINVAL;
      return -1;
    }

  if ((fd = get_connection_fd ()) < 0)
    return -1;
  fp = OVAS_CONNECTION_FROM_FD (fd);

  fp->transport = transport;
  g_free (fp->priority);
  if (*priority)
    fp->priority = g_strdup (priority);
  else
    fp->priority = NULL;
  fp->timeout = timeout;
  fp->port = port;
  fp->last_err = 0;
  set_ids_evasion_mode (args, fp);

  if (fp->options & OPENVAS_CNX_IDS_EVASION_FAKE_RST)
    fp->fd = ids_open_sock_tcp (args, port, fp->options, timeout);
  else
    fp->fd = open_sock_tcp (args, port, timeout);

  if (fp->fd < 0)
    goto failed;

  kb_t kb = plug_get_kb (args);
  switch (transport)
    {
    int ret;
    char buf[1024];
    case OPENVAS_ENCAPS_IP:
      break;
    case OPENVAS_ENCAPS_SSLv23:
    case OPENVAS_ENCAPS_SSLv3:
    case OPENVAS_ENCAPS_TLSv1:
    case OPENVAS_ENCAPS_TLSv11:
    case OPENVAS_ENCAPS_TLSv12:
    case OPENVAS_ENCAPS_TLScustom:
      renice_myself ();
      cert = kb_item_get_str (kb, "SSL/cert");
      key = kb_item_get_str (kb, "SSL/key");
      passwd = kb_item_get_str (kb, "SSL/password");

      cafile = kb_item_get_str (kb, "SSL/CA");

      /* fall through */

    case OPENVAS_ENCAPS_SSLv2:
      /* We do not need a client certificate in this case */
      snprintf (buf, sizeof (buf), "Host/SNI/%d/force_disable", fp->port);
      if (kb_item_get_int (kb, buf) <= 0)
        hostname = plug_get_host_fqdn (args);
      ret = open_SSL_connection (fp, cert, key, passwd, cafile, hostname);
      g_free (cert);
      g_free (key);
      g_free (passwd);
      g_free (cafile);
      if (ret <= 0)
        goto failed;
      break;
    }

  return fd;

failed:
  release_connection_fd (fd, 0);
  return -1;
}


int
open_stream_connection (struct arglist *args, unsigned int port,
                        int transport, int timeout)
{
  return open_stream_connection_ext (args, port, transport, timeout,
                                     "NORMAL:+ARCFOUR-128:%COMPAT");
}

/* Same as open_stream_auto_encaps but allows to force auto detection
   of the protocols if FORCE is true.  */
int
open_stream_auto_encaps_ext (struct arglist *args, unsigned int port,
                             int timeout, int force)
{
  int fd, transport;

  if (force)
    {
      /* Try SSL/TLS first */
      transport = OPENVAS_ENCAPS_TLScustom;
      fd = open_stream_connection (args, port, transport, timeout);
      if (fd < 0)
        {
          transport = OPENVAS_ENCAPS_IP;
          fd = open_stream_connection (args, port, OPENVAS_ENCAPS_IP, timeout);
          if (fd < 0)
            return -1;
        }
      /* Store that encapsulation mode in the KB.  */
      plug_set_port_transport (args, port, transport);
      return fd;
    }
  else
    {
      transport = plug_get_port_transport (args, port);
      fd = open_stream_connection (args, port, transport, timeout);
      return fd;
    }
 /*NOTREACHED*/
}

int
stream_set_timeout (int fd, int timeout)
{
  int old;
  openvas_connection *fp;
  if (!OPENVAS_STREAM (fd))
    {
      errno = EINVAL;
      return 0;
    }
  fp = OVAS_CONNECTION_FROM_FD (fd);
  old = fp->timeout;
  fp->timeout = timeout;
  return old;
}

static int
read_stream_connection_unbuffered (int fd, void *buf0, int min_len, int max_len)
{
  int ret, realfd, trp, t;
  int total = 0, flag = 0, timeout = TIMEOUT, waitall = 0;
  unsigned char *buf = (unsigned char *) buf0;
  openvas_connection *fp = NULL;
  fd_set fdr, fdw;
  struct timeval tv;
  time_t now, then;

  int select_status;

#if 0
  log_lecacy_write ("read_stream_connection(%d, 0x%x, %d, %d)\n", fd, buf,
                    min_len, max_len);
#endif

  if (OPENVAS_STREAM (fd))
    {
      fp = OVAS_CONNECTION_FROM_FD (fd);
      trp = fp->transport;
      realfd = fp->fd;
      fp->last_err = 0;
      if (fp->timeout != -2)
        timeout = fp->timeout;
    }
  else
    {
#if 0
      log_lecacy_write ("read_stream_connection[%d] : supposedly bad fd %d\n",
                        getpid (), fd);
#endif
      trp = OPENVAS_ENCAPS_IP;
      if (fd < 0 || fd > 1024)
        {
          errno = EBADF;
          return -1;
        }
      realfd = fd;
    }

#ifndef INCR_TIMEOUT
# define INCR_TIMEOUT	1
#endif

  if (min_len == max_len || timeout <= 0)
    waitall = MSG_WAITALL;
  if (trp == OPENVAS_ENCAPS_IP)
    {
      for (t = 0; total < max_len && (timeout <= 0 || t < timeout);)
        {
          tv.tv_sec = INCR_TIMEOUT;     /* Not timeout! */
          tv.tv_usec = 0;
          FD_ZERO (&fdr);
          FD_SET (realfd, &fdr);
          if (select (realfd + 1, &fdr, NULL, NULL, timeout > 0 ? &tv : NULL) <=
              0)
            {
              t += INCR_TIMEOUT;
              /* Try to be smart */
              if (total > 0 && flag)
                return total;
              else if (total >= min_len)
                flag++;
            }
          else
            {
              errno = 0;
              ret = recv (realfd, buf + total, max_len - total, waitall);
              if (ret < 0)
                if (errno != EINTR)
                  {
                    fp->last_err = errno;
                    return total;
                  }
                else
                  ret = 0;
              else if (ret == 0)        /* EOF */
                {
                  fp->last_err = EPIPE;
                  return total;
                }
              /*ret > 0 */
              total += ret;
              if (min_len > 0 && total >= min_len)
                return total;
              flag = 0;
            }
        }
      if (t >= timeout)
        fp->last_err = ETIMEDOUT;
      return total;
    }

  switch (trp)
    {
      /* OPENVAS_ENCAPS_IP was treated before with the non-OpenVAS fd */
    case OPENVAS_ENCAPS_SSLv2:
    case OPENVAS_ENCAPS_SSLv23:
    case OPENVAS_ENCAPS_SSLv3:
    case OPENVAS_ENCAPS_TLSv1:
    case OPENVAS_ENCAPS_TLSv11:
    case OPENVAS_ENCAPS_TLSv12:
    case OPENVAS_ENCAPS_TLScustom:
# if DEBUG_SSL > 0
      if (getpid () != fp->pid)
        {
          log_lecacy_write ("PID %d tries to use a SSL connection established "
                            "by PID %d\n",
                            getpid (), fp->pid);
          errno = EINVAL;
          return -1;
        }
# endif

      then = time (NULL);
      for (t = 0; timeout <= 0 || t < timeout; t = now - then)
        {
          now = time (NULL);
          tv.tv_sec = INCR_TIMEOUT;
          tv.tv_usec = 0;
          FD_ZERO (&fdr);
          FD_ZERO (&fdw);
          FD_SET (realfd, &fdr);
          FD_SET (realfd, &fdw);

          select_status = select (realfd + 1, &fdr, &fdw, NULL, &tv);

          if (select_status > 0)
            {
              /* TLS FIXME: handle rehandshake */
              ret =
                gnutls_record_recv (fp->tls_session, buf + total,
                                    max_len - total);
              if (ret > 0)
                {
                  total += ret;
                  if (total >= max_len)
                    return total;
                }
              else if (ret != GNUTLS_E_INTERRUPTED && ret != GNUTLS_E_AGAIN)
                {
                  /* This branch also handles the case where ret == 0,
                   * i.e. that the connection has been closed.  This is
                   * for compatibility with the old OpenSSL based openvas
                   * code which treated SSL_ERROR_ZERO_RETURN as an
                   * error too.
                   */
#ifdef DEBUG_SSL
                  if (ret < 0)
                    {
                      tlserror ("gnutls_record_recv", ret);
                    }
                  else
                    {
                      log_lecacy_write ("gnutls_record_recv[%d]: EOF\n",
                                        getpid ());
                    }
#endif
                  fp->last_err = EPIPE;
                  return total;
                }
            }

          if (min_len > 0 && total >= min_len)
            return total;
        }
      if (t >= timeout)
        fp->last_err = ETIMEDOUT;
      return total;

    default:
      if (fp->transport || fp->fd != 0)
        log_legacy_write ("Severe bug! Unhandled transport layer %d (fd=%d)\n",
                          fp->transport, fd);
      else
        log_legacy_write ("read_stream_connection_unbuffered: "
                          "fd=%d is closed\n",
                          fd);
      errno = EINVAL;
      return -1;
    }
 /*NOTREACHED*/
}

int
read_stream_connection_min (int fd, void *buf0, int min_len, int max_len)
{
  openvas_connection *fp;

  if (OPENVAS_STREAM (fd))
    {
      fp = OVAS_CONNECTION_FROM_FD (fd);
      if (fp->buf != NULL)
        {
          int l1, l2;

          if (max_len == 1)
            min_len = 1;        /* avoid "magic read" later */
          l2 = max_len > fp->bufcnt ? fp->bufcnt : max_len;
          if (l2 > 0)
            {
              memcpy (buf0, fp->buf + fp->bufptr, l2);
              fp->bufcnt -= l2;
              if (fp->bufcnt == 0)
                {
                  fp->bufptr = 0;
                  fp->buf[0] = '\0';    /* debug */
                }
              else
                fp->bufptr += l2;
              if (l2 >= min_len || l2 >= max_len)
                return l2;
              max_len -= l2;
              min_len -= l2;
            }
          if (min_len > fp->bufsz)
            {
              l1 =
                read_stream_connection_unbuffered (fd, (char *) buf0 + l2,
                                                   min_len, max_len);
              if (l1 > 0)
                return l1 + l2;
              else
                return l2;
            }
          /* Fill buffer */
          l1 =
            read_stream_connection_unbuffered (fd, fp->buf, min_len, fp->bufsz);
          if (l1 <= 0)
            return l2;

          fp->bufcnt = l1;
          l1 = max_len > fp->bufcnt ? fp->bufcnt : max_len;
          memcpy ((char *) buf0 + l2, fp->buf + fp->bufptr, l1);
          fp->bufcnt -= l1;
          if (fp->bufcnt == 0)
            fp->bufptr = 0;
          else
            fp->bufptr += l1;
          return l1 + l2;
        }
    }
  return read_stream_connection_unbuffered (fd, buf0, min_len, max_len);
}

int
read_stream_connection (int fd, void *buf0, int len)
{
  return read_stream_connection_min (fd, buf0, -1, len);
}

static int
write_stream_connection4 (int fd, void *buf0, int n, int i_opt)
{
  int ret, count;
  unsigned char *buf = (unsigned char *) buf0;
  openvas_connection *fp;
  fd_set fdr, fdw;
  struct timeval tv;
  int e;

  if (!OPENVAS_STREAM (fd))
    {
#if DEBUG_SSL > 0
      log_lecacy_write ("write_stream_connection: fd <%d> invalid\n", fd);
# if 0
      abort ();
# endif
#endif
      errno = EINVAL;
      return -1;
    }

  fp = OVAS_CONNECTION_FROM_FD (fd);
  fp->last_err = 0;

#if DEBUG_SSL > 8
  log_lecacy_write (
           "> write_stream_connection(%d, %s, %d, 0x%x) \tE=%d 0=0x%x\n", fd,
           buf, n, i_opt, fp->transport, fp->options);
#endif

  switch (fp->transport)
    {
    case OPENVAS_ENCAPS_IP:
      for (count = 0; count < n;)
        {
          if ((fp->options & OPENVAS_CNX_IDS_EVASION_SEND_MASK) != 0)
            {
              if (fp->options & OPENVAS_CNX_IDS_EVASION_SPLIT)
                /* IDS evasion */
                ret = send (fp->fd, buf + count, 1, i_opt);
              else
                /* i_opt ignored for ids_send */
                ret = ids_send (fp->fd, buf + count, n - count, fp->options);
            }
          else
            ret = send (fp->fd, buf + count, n - count, i_opt);

          if (ret <= 0)
            {
              if (ret < 0)
                fp->last_err = errno;
              else
                fp->last_err = EPIPE;
              break;
            }

          count += ret;
        }
      break;

    case OPENVAS_ENCAPS_SSLv2:
    case OPENVAS_ENCAPS_SSLv23:
    case OPENVAS_ENCAPS_SSLv3:
    case OPENVAS_ENCAPS_TLSv1:
    case OPENVAS_ENCAPS_TLSv11:
    case OPENVAS_ENCAPS_TLSv12:
    case OPENVAS_ENCAPS_TLScustom:

      /* i_opt ignored for SSL */
      for (count = 0; count < n;)
        {
          ret = gnutls_record_send (fp->tls_session, buf + count, n - count);

          if (ret > 0)
            {
              count += ret;
            }
          else if (ret != GNUTLS_E_INTERRUPTED && ret != GNUTLS_E_AGAIN)
            {
              /* This branch also handles the case where ret == 0,
               * i.e. that the connection has been closed.  This is
               * for compatibility with the old openvas code which
               * treated SSL_ERROR_ZERO_RETURN as an error too.
               */
#ifdef DEBUG_SSL
              if (ret < 0)
                {
                  tlserror ("gnutls_record_send", ret);
                }
              else
                {
                  log_lecacy_write ("gnutls_record_send[%d]: EOF\n", getpid ());
                }
#endif
              fp->last_err = EPIPE;
              break;
            }

          if (fp->timeout >= 0)
            tv.tv_sec = fp->timeout;
          else
            tv.tv_sec = TIMEOUT;
          tv.tv_usec = 0;

          do
            {
              errno = 0;
              FD_ZERO (&fdr);
              FD_ZERO (&fdw);
              FD_SET (fp->fd, &fdr);
              FD_SET (fp->fd, &fdw);
              e = select (fp->fd + 1, &fdr, &fdw, NULL, &tv);
            }
          while (e < 0 && errno == EINTR);

          if (e <= 0)
            {
#if DEBUG_SSL > 0
              pid_perror ("select");
#endif
              fp->last_err = ETIMEDOUT;
              break;
            }
        }
      break;

    default:
      if (fp->transport || fp->fd != 0)
        log_legacy_write ("Severe bug! Unhandled transport layer %d (fd=%d)\n",
                          fp->transport, fd);
      else
        log_legacy_write ("read_stream_connection_unbuffered: fd=%d is "
                          "closed\n", fd);
      errno = EINVAL;
      return -1;
    }

  if (count == 0 && n > 0)
    return -1;
  else
    return count;
}

int
write_stream_connection (int fd, void *buf0, int n)
{
  return write_stream_connection4 (fd, buf0, n, 0);
}

int
nsend (int fd, void *data, int length, int i_opt)
{
  int n = 0;

  if (OPENVAS_STREAM (fd))
    {
      if (connections[fd - OPENVAS_FD_OFF].fd < 0)
        log_legacy_write ("OpenVAS file descriptor %d closed ?!\n", fd);
      else
        return write_stream_connection4 (fd, data, length, i_opt);
    }
  /* Trying OS's send() */
  block_socket (fd);            /* ??? */
  do
    {
      struct timeval tv = {
        0, 5
      };
      fd_set wr;
      int e;

      FD_ZERO (&wr);
      FD_SET (fd, &wr);

      errno = 0;
      e = select (fd + 1, NULL, &wr, NULL, &tv);
      if (e > 0)
        n = os_send (fd, data, length, i_opt);
      else if (e < 0 && errno == EINTR)
        continue;
      else
        break;
    }
  while (n <= 0 && errno == EINTR);
  if (n < 0)
    log_legacy_write ("[%d] nsend():send %s\n", getpid (), strerror (errno));

  return n;
}

int
nrecv (int fd, void *data, int length, int i_opt)
{
  int e;
#if DEBUG_SSL > 8
  log_legacy_write ("nrecv: fd=%d len=%d\n", fd, length);
#endif
  if (OPENVAS_STREAM (fd))
    {
      if (connections[fd - OPENVAS_FD_OFF].fd < 0)
        log_legacy_write ("OpenVAS file descriptor %d closed ?!\n", fd);
      else
        return read_stream_connection (fd, data, length);
    }
  /* Trying OS's recv()
   *
   * Do *NOT* use os_recv() here, as it will be blocking until the exact
   * amount of requested data arrives
   */
  block_socket (fd);
  do
    {
      e = recv (fd, data, length, i_opt);
    }
  while (e < 0 && errno == EINTR);
  return e;
}


/**
 * @brief Register a hook function for close_stream_connection.
 *
 * The function adds the given hook function to the list of hooks to
 * be run by close_stream_connection.  These hooks are intended to
 * test whether they need to close the stream them self.  See argument
 * to the hook function is the file descriptor of the stream.  The
 * hook shall return 0 if it has taken over control of that file
 * descriptor.  The same function is only aded once to the list of
 * hooks.
 *
 * @param fnc  The hook function.  See above for details.
 */
void
add_close_stream_connection_hook (int (*fnc)(int fd))
{
  struct csc_hook_s *hook;

  for (hook = csc_hooks; hook; hook = hook->next)
    if (hook->fnc == fnc)
      return; /* Already added.  */

  hook = g_malloc0 (sizeof *hook);
  hook->fnc = fnc;
  hook->next = csc_hooks;
  csc_hooks = hook;
}

/**
 * @brief Run the hooks for close_stream_connection.
 *
 * The function runs all registered hooks until the first hook returns
 * with zero to indicate that it has taken over control of the socket.
 * Further hooks are then not anymore run because the file descriptor
 * is not anymore valid.
 *
 * @param fd The file descriptor of the stream.

 * @return Zero if one of the hooks has closed the connection;
 *         non-zero otherwise.
 */
static int
run_csc_hooks (int fd)
{
  struct csc_hook_s *hook;

  for (hook = csc_hooks; hook; hook = hook->next)
    if (hook->fnc && !hook->fnc (fd))
      return 0;
  return -1;
}

int
close_stream_connection (int fd)
{
#if DEBUG_SSL > 2
  openvas_connection *fp;
  if (!OPENVAS_STREAM (fd))
    {
      errno = EINVAL;
      return -1;
    }
  fp = OVAS_CONNECTION_FROM_FD (fd);
  log_legacy_write ("close_stream_connection TCP:%d (fd=%d)\n", fp->port, fd);
#endif

  if (!OPENVAS_STREAM (fd))     /* Will never happen if debug is on! */
    {
      if (fd < 0 || fd > 1024)
        {
          errno = EINVAL;
          return -1;
        }
      shutdown (fd, 2);
      return socket_close (fd);
    }
  if (!run_csc_hooks (fd))
    return release_connection_fd (fd, 1);
  else
    return release_connection_fd (fd, 0);
}

const char *
get_encaps_name (openvas_encaps_t code)
{
  static char str[100];
  switch (code)
    {
    case OPENVAS_ENCAPS_AUTO:
      return "auto";
    case OPENVAS_ENCAPS_IP:
      return "IP";
    case OPENVAS_ENCAPS_SSLv2:
      return "SSLv2";
    case OPENVAS_ENCAPS_SSLv23:
      return "SSLv23";
    case OPENVAS_ENCAPS_SSLv3:
      return "SSLv3";
    case OPENVAS_ENCAPS_TLSv1:
      return "TLSv1";
    case OPENVAS_ENCAPS_TLSv11:
      return "TLSv11";
    case OPENVAS_ENCAPS_TLSv12:
      return "TLSv12";
    case OPENVAS_ENCAPS_TLScustom:
      return "TLScustom";
    default:
      snprintf (str, sizeof (str), "[unknown transport layer - code %d (0x%x)]", code, code);
      return str;
    }
}

const char *
get_encaps_through (openvas_encaps_t code)
{
  static char str[100];
  switch (code)
    {
    case OPENVAS_ENCAPS_IP:
      return "";
    case OPENVAS_ENCAPS_SSLv2:
    case OPENVAS_ENCAPS_SSLv23:
    case OPENVAS_ENCAPS_SSLv3:
    case OPENVAS_ENCAPS_TLSv1:
    case OPENVAS_ENCAPS_TLSv11:
    case OPENVAS_ENCAPS_TLSv12:
    case OPENVAS_ENCAPS_TLScustom:
      return " through SSL";
    default:
      snprintf (str, sizeof (str), " through unknown transport layer - code %d (0x%x)", code, code);
      return str;
    }
}

static int
open_socket (struct sockaddr *paddr, int type, int protocol,
             int timeout, int len)
{
  fd_set fd_w;
  struct timeval to;
  int soc, x;
  int opt;
  unsigned int opt_sz;
  int family;

  __port_closed = 0;

  if (paddr->sa_family == AF_INET)
    {
      family = AF_INET;
      if ((soc = socket (AF_INET, type, protocol)) < 0)
        {
          pid_perror ("socket");
          return -1;
        }
    }
  else
    {
      family = AF_INET6;
      if ((soc = socket (AF_INET6, type, protocol)) < 0)
        {
          pid_perror ("socket");
          return -1;
        }
    }

  if (timeout == -2)
    timeout = TIMEOUT;

  if (timeout > 0)
    if (unblock_socket (soc) < 0)
      {
        close (soc);
        return -1;
      }

  openvas_source_set_socket (soc, 0, family);

  if (connect (soc, paddr, len) < 0)
    {
#if DEBUG_SSL > 2
      pid_perror ("connect");
#endif
    again:
      switch (errno)
        {
        case EINPROGRESS:
        case EAGAIN:
          FD_ZERO (&fd_w);
          FD_SET (soc, &fd_w);
          to.tv_sec = timeout;
          to.tv_usec = 0;
          x = select (soc + 1, NULL, &fd_w, NULL, &to);
          if (x == 0)
            {
#if DEBUG_SSL > 2
              pid_perror ("connect->select: timeout");
#endif
              socket_close (soc);
              errno = ETIMEDOUT;
              return -1;
            }
          else if (x < 0)
            {
              if (errno == EINTR)
                {
                  errno = EAGAIN;
                  goto again;
                }
              pid_perror ("select");
              socket_close (soc);
              return -1;
            }

          opt = 0;
          opt_sz = sizeof (opt);
          if (getsockopt (soc, SOL_SOCKET, SO_ERROR, &opt, &opt_sz) < 0)
            {
              pid_perror ("getsockopt");
              socket_close (soc);
              return -1;
            }
          if (opt == 0)
            break;
#if DEBUG_SSL > 2
          errno = opt;
          pid_perror ("SO_ERROR");
#endif
          /* fallthrough */
        default:
          __port_closed = 1;
          socket_close (soc);
          return -1;
        }
    }
  block_socket (soc);
  return soc;
}



int
open_sock_opt_hn (const char *hostname, unsigned int port, int type,
                  int protocol, int timeout)
{
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  struct in6_addr in6addr;

  openvas_resolve_as_addr6 (hostname, &in6addr);
  if (IN6_IS_ADDR_V4MAPPED (&in6addr))
    {
      bzero ((void *) &addr, sizeof (addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons ((unsigned short) port);
      addr.sin_addr.s_addr = in6addr.s6_addr32[3];
      return open_socket ((struct sockaddr *) &addr, type, protocol,
                          timeout, sizeof (struct sockaddr_in));
    }
  else
    {
      bzero ((void *) &addr6, sizeof (addr6));
      addr6.sin6_family = AF_INET6;
      addr6.sin6_port = htons ((unsigned short) port);
      memcpy (&addr6.sin6_addr, &in6addr, sizeof (struct in6_addr));
      return open_socket ((struct sockaddr *) &addr6, type, protocol,
                          timeout, sizeof (struct sockaddr_in6));
    }

}

int
open_sock_tcp (struct arglist *args, unsigned int port, int timeout)
{
  int ret, retry = 0;
  const char *timeout_retry;

  timeout_retry = prefs_get ("timeout_retry");
  if (timeout_retry)
    retry = atoi (timeout_retry);
  if (retry < 0)
    retry = 0;

  while (retry >= 0)
    {
      errno = 0;
      ret = open_sock_option (args, port, SOCK_STREAM, IPPROTO_TCP, timeout);
      if (ret >= 0 || errno != ETIMEDOUT)
        break;
      retry--;
    }
  if (ret < 0 && errno == ETIMEDOUT)
    {
      int log_count;
      char *ip_str = plug_get_host_ip_str (args), buffer[1024];
      kb_t kb = plug_get_kb (args);

      g_snprintf (buffer, sizeof (buffer), "ConnectTimeout/%s/%d", ip_str,
                  port);
      log_count = kb_item_get_int (kb, buffer);
      if (log_count == -1)
        log_count = 0;
      if (log_count < 3)
        log_legacy_write ("open_sock_tcp: %s:%d time-out.", ip_str, port);
      log_count++;
      kb_item_set_int (kb, buffer, log_count);
      g_free (ip_str);
    }

  return ret;
}


int
open_sock_option (struct arglist *args, unsigned int port, int type,
                  int protocol, int timeout)
{
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  struct in6_addr *t;

#if 0
  /*
   * MA 2004-08-15: IMHO, as this is often (always?) tested in the NASL scripts
   * this should not be here.
   * If it has to be somewhere else, I'd rather put it in libnasl (and add
   * a parameter to "force" the connection)
   */
  if (host_get_port_state (args, port) <= 0)
    return (-1);
#endif
  t = plug_get_host_ip (args);
  if (!t)
    {
      log_legacy_write ("ERROR ! NO ADDRESS ASSOCIATED WITH NAME\n");
      arg_dump (args, 0);
      return (-1);
    }
  if (IN6_ARE_ADDR_EQUAL (t, &in6addr_any))
    return (-1);
  if (IN6_IS_ADDR_V4MAPPED (t))
    {
      bzero ((void *) &addr, sizeof (addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons ((unsigned short) port);
      addr.sin_addr.s_addr = t->s6_addr32[3];
      return open_socket ((struct sockaddr *) &addr, type, protocol,
                          timeout, sizeof (struct sockaddr_in));
    }
  else
    {
      bzero ((void *) &addr6, sizeof (addr6));
      addr6.sin6_family = AF_INET6;
      addr6.sin6_port = htons ((unsigned short) port);
      memcpy (&addr6.sin6_addr, t, sizeof (struct in6_addr));
      return open_socket ((struct sockaddr *) &addr6, type, protocol,
                          timeout, sizeof (struct sockaddr_in6));
    }

}


/**
 * @brief Reads a text from the socket stream into the argument buffer, always
 * @brief appending a '\\0' byte.
 *
 * @param buf  Buffer to read into.
 *
 * @return Number of bytes read, without the trailing '\\0'.
 */
int
recv_line (int soc, char *buf, size_t bufsiz)
{
  int n;
  unsigned int ret = 0;

  /* Dirty SSL hack */
  if (OPENVAS_STREAM (soc))
    {
      unsigned int ret = 0;
      buf[0] = '\0';

      do
        {
          n = read_stream_connection_min (soc, buf + ret, 1, 1);
          switch (n)
            {
            case -1:
              if (ret == 0)
                return -1;
              else
                return ret;
              break;

            case 0:
              return ret;
              break;

            default:
              ret++;
            }
        }
      while (buf[ret - 1] != '\0' && buf[ret - 1] != '\n' && ret < bufsiz);

      if (ret > 0)
        {
          if (buf[ret - 1] != '\0')
            {
              if (ret < bufsiz)
                buf[ret] = '\0';
              else
                buf[bufsiz - 1] = '\0';
            }
        }

      return ret;
    }
  else
    {
      fd_set rd;

      do
        {
          int e;
        again:
          errno = 0;
          FD_ZERO (&rd);
          FD_SET (soc, &rd);
          e = select (soc + 1, &rd, NULL, NULL, NULL);
          if (e == 0 && !FD_ISSET (soc, &rd))
            return -1;
          if (e < 0 && errno == EINTR)
            goto again;
          if (e > 0)
            {
              n = recv (soc, buf + ret, 1, 0);
              switch (n)
                {
                case -1:
                  if (errno == EINTR)
                    continue;
                  if (ret == 0)
                    return -1;
                  else
                    return ret;
                  break;
                case 0:
                  return ret;
                  break;
                default:
                  ret++;
                }
            }
          else
            break;
        }
      while (buf[ret - 1] != '\0' && buf[ret - 1] != '\n' && ret < bufsiz);

      if (ret > 0)
        {
          if (buf[ret - 1] != '\0')
            {
              if (ret < bufsiz)
                buf[ret] = '\0';
              else
                buf[bufsiz - 1] = '\0';
            }
        }
    }

  return ret;
}

int
socket_close (int soc)
{
  return close (soc);
}

/*
 * Select() routines
 */

int
stream_zero (fd_set * set)
{
  FD_ZERO (set);
  return 0;
}

int
stream_set (int fd, fd_set * set)
{
  int soc = openvas_get_socket_from_connection (fd);
  if (soc >= 0)
    FD_SET (soc, set);
  return soc;
}

int
fd_is_stream (int fd)
{
  return OPENVAS_STREAM (fd);   /* Should probably be smarter... */
}


int
stream_get_buffer_sz (int fd)
{
  openvas_connection *p;
  if (!OPENVAS_STREAM (fd))
    return -1;
  p = OVAS_CONNECTION_FROM_FD (fd);
  return p->bufsz;
}

int
stream_set_buffer (int fd, int sz)
{
  openvas_connection *p;
  char *b;

  if (!OPENVAS_STREAM (fd))
    return -1;

  p = OVAS_CONNECTION_FROM_FD (fd);
  if (sz < p->bufcnt)
    return -1;                  /* Do not want to lose data */

  if (sz == 0)
    {
      g_free (p->buf);
      p->buf = NULL;
      p->bufsz = 0;
      return 0;
    }
  else if (p->buf == 0)
    {
      p->buf = g_malloc0 (sz);
      if (p->buf == NULL)
        return -1;
      p->bufsz = sz;
      p->bufptr = 0;
      p->bufcnt = 0;
      return 0;
    }
  else
    {
      if (p->bufcnt > 0)
        {
          memmove (p->buf, p->buf + p->bufptr, p->bufcnt);
          p->bufptr = 0;
        }
      b = g_realloc (p->buf, sz);
      if (b == NULL)
        return -1;
      p->buf = b;
      p->bufsz = sz;
      return 0;
    }
 /*NOTREACHED*/}



/*------------------------------------------------------------------*/


int
os_send (int soc, void *buf, int len, int opt)
{
  char *buf0 = (char *) buf;
  int e, n;
  for (n = 0; n < len;)
    {
      errno = 0;
      e = send (soc, buf0 + n, len - n, opt);
      if (e < 0 && errno == EINTR)
        continue;
      else if (e <= 0)
        return -1;
      else
        n += e;
    }
  return n;
}

int
os_recv (int soc, void *buf, int len, int opt)
{
  char *buf0 = (char *) buf;
  int e, n;
  for (n = 0; n < len;)
    {
      errno = 0;
      e = recv (soc, buf0 + n, len - n, opt);
      if (e < 0 && errno == EINTR)
        continue;
      else if (e <= 0)
        return -1;
      else
        n += e;
    }
  return n;
}

/** @todo internal_send and internal_recv. could make an own module (ipc), in
 *        which the type constants could be moved, too. */

/**
 * internal_send() / internal_recv() :
 *
 * When processes are passing messages to each other, the format is
 * <length><msg>, with <length> being a long integer. The functions
 * internal_send() and internal_recv() encapsulate and decapsulate
 * the messages themselves.
 */
int
internal_send (int soc, char *data, int msg_type)
{
  int len;
  int e;
  int ack;

  if (data == NULL)
    data = "";

  e = os_send (soc, &msg_type, sizeof (msg_type), 0);
  if (e < 0)
    return -1;

  if ((msg_type & INTERNAL_COMM_MSG_TYPE_CTRL) == 0)
    {
      len = strlen (data);

      e = os_send (soc, &len, sizeof (len), 0);
      if (e < 0)
        return -1;
      e = os_send (soc, data, len, 0);
      if (e < 0)
        return -1;
    }

  e = os_recv (soc, &ack, sizeof (ack), 0);
  if (e < 0)
    {
      log_legacy_write ("internal_send->os_recv(%d): %s\n", soc,
                        strerror (errno));
      return -1;
    }

  return 0;
}

/**
 * internal_send() / internal_recv() :
 *
 * When processes are passing messages to each other, the format is
 * \<length\>\<msg\>, with \<length\> being a long integer. The functions
 * internal_send() and internal_recv() encapsulate and decapsulate
 * the messages themselves.
 *
 * @param[in]   soc         The socket from which to receive message.
 * @param[out]  data        Where to allocate the reception buffer. Has to be
 *                          set to NULL, and left untouched on failure or
 *                          zero-length messages.
 * @param[out]  data_sz     Size of the received message.
 * @param[out]  msg_type    Type of the message which was received.
 *
 * @retval Length of the received message on success (can be zero).
 * @retval Negative value on error.
 */
int
internal_recv (int soc, char **data, int *data_sz, int *msg_type)
{
  int len = 0;
  int e;
  char *buf = NULL;
  int sz = 0;
  int type;
  int ack;

  if (*data != NULL)
    {
      log_legacy_write("%s doesn't support buffer pre-alloc anymore.", __func__);
      return -1;
    }

  e = os_recv (soc, &type, sizeof (type), 0);
  if (e < 0)
    goto error;

  if ((type & INTERNAL_COMM_MSG_TYPE_CTRL) == 0)
    {
      e = os_recv (soc, &len, sizeof (len), 0);
      if (e < 0 || len < 0)
        goto error;

      /* length == 0 is perfectly valid though */
      if (len > 0)
        {
          sz = len + 1;
          buf = g_malloc0 (sz);

          e = os_recv (soc, buf, len, 0);
          if (e < 0)
            goto error;
        }
    }

  *data     = buf;
  *data_sz  = sz;
  *msg_type = type;

  ack = INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_ACK;
  e = os_send (soc, &ack, sizeof (ack), 0);
  if (e < 0)
    goto error;

  return len;

error:
  g_free (buf);
  *data = NULL;
  *data_sz = 0;
  return -1;
}

/* This is a helper function for nasl_get_sock_info.  It is used to
   retrieve information about SOCK.  */
int
get_sock_infos (int sock, int *r_transport, void **r_tls_session)
{
  openvas_connection *fp;

  if (!OPENVAS_STREAM (sock))
    return ENOTSOCK;
  fp = &(connections[sock - OPENVAS_FD_OFF]);

  *r_transport = fp->transport;
  *r_tls_session = fp->tls_session;
  return 0;
}

/*
 * 0 is considered as the biggest number, since it
 * ends our string
 */
static int
qsort_compar (const void *a, const void *b)
{
  u_short *aa = (u_short *) a;
  u_short *bb = (u_short *) b;
  if (*aa == 0)
    return (1);
  else if (*bb == 0)
    return (-1);
  else
    return (*aa - *bb);
}

/**
 * @brief Converts a string like "-100,200-1024,3000-4000,60000-" into an array
 * @brief of port numbers
 *
 * This function is (c) Fyodor <fyodor@dhp.com> and was taken from
 * his excellent and outstanding scanner Nmap
 * See http://www.insecure.org/nmap/ for details about
 * Nmap
 */
unsigned short *
getpts (char *origexpr, int *len)
{
  int exlen;
  char *p, *q;
  unsigned short *tmp, *ports;
  int i = 0, j = 0, start, end;
  char *expr;
  char *mem;
  char *s_start, *s_end;
  static unsigned short *last_ret = NULL;
  static char *last_expr = NULL;
  static int last_num;

  expr = g_strdup (origexpr);
  exlen = strlen (origexpr);
  mem = expr;

  if (last_expr != NULL)
    {
      if (strcmp (last_expr, expr) == 0)
        {
          if (len != NULL)
            *len = last_num;
          g_free (mem);
          return last_ret;
        }
      else
        {
          g_free (last_expr);
          last_expr = NULL;
          g_free (&last_ret);
          last_ret = NULL;
        }
    }

  ports = g_malloc0 (65536 * sizeof (short));
  for (; j < exlen; j++)
    if (expr[j] != ' ')
      expr[i++] = expr[j];
  expr[i] = '\0';

  if ((s_start = strstr (expr, "T:")) != NULL)
    expr = &(s_start[2]);

  if ((s_end = strstr (expr, "U:")) != NULL)
    {
      if (s_end[-1] == ',')
        s_end--;
      s_end[0] = '\0';
    }

  i = 0;
  while ((p = strchr (expr, ',')))
    {
      *p = '\0';
      if (*expr == '-')
        {
          start = 1;
          end = atoi (expr + 1);
        }
      else
        {
          start = end = atoi (expr);
          if ((q = strchr (expr, '-')) && *(q + 1))
            end = atoi (q + 1);
          else if (q && !*(q + 1))
            end = 65535;
        }
      if (start < 1)
        start = 1;
      if (start > end)
        {
          g_free (mem);
          g_free (ports);
          return NULL;
        }
      for (j = start; j <= end; j++)
        ports[i++] = j;
      expr = p + 1;
    }
  if (*expr == '-')
    {
      start = 1;
      end = atoi (expr + 1);
    }
  else
    {
      start = end = atoi (expr);
      if ((q = strchr (expr, '-')) && *(q + 1))
        end = atoi (q + 1);
      else if (q && !*(q + 1))
        end = 65535;
    }
  if (start < 1)
    start = 1;
  if (start > end)
    {
      g_free (mem);
      g_free (ports);
      return NULL;
    }
  for (j = start; j <= end; j++)
    ports[i++] = j;
  ports[i++] = 0;

  qsort (ports, i, sizeof (u_short), qsort_compar);
  tmp = g_realloc (ports, i * sizeof (short));
  if (len != NULL)
    *len = i - 1;
  g_free (mem);

  last_ret = tmp;
  last_expr = g_strdup (origexpr);
  last_num = i - 1;
  return tmp;
}

/**
 * @brief Initializes a host_info.
 *
 * @param[in]   name        Hostname.
 * @param[in]   ip          IP address.
 * @param[in]   vhosts      Vhosts list.
 * @param[in]   fqdn        Fully qualified domain name.
 *
 * @return host_info pointer.
 */
struct host_info *
host_info_init (const char *name, const struct in6_addr *ip,
                const char *vhosts, const char *fqdn)
{
  struct host_info *hostinfo;

  hostinfo = g_malloc0 (sizeof (struct host_info));
  hostinfo->name = g_strdup (name);
  hostinfo->fqdn = g_strdup (fqdn);
  hostinfo->vhosts = g_strdup (vhosts);
  if (ip)
    {
      hostinfo->ip = g_malloc0 (sizeof (struct in6_addr));
      memcpy (hostinfo->ip, ip, sizeof (struct in6_addr));
    }
  return hostinfo;
}

/**
 * @brief Free a host_info struct.
 *
 * @param[in]   hostinfo    Host info to free.
 */
void
host_info_free (struct host_info *hostinfo)
{
  if (!hostinfo)
    return;
  g_free (hostinfo->name);
  g_free (hostinfo->fqdn);
  g_free (hostinfo->vhosts);
  g_free (hostinfo->ip);
}
