/**
 * GnuTLS based functions for communication with an OpenVAS server.
 * Copyright (C) 2009, 2012  Greenbone Networks GmbH
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 * Werner Koch <wk@gnupg.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/**
 * @file openvas_server.c
 * @brief GnuTLS based functions for communication with an OpenVAS server.
 *
 * This library supplies low-level communication functions for communication
 * with an OpenVAS server over GnuTLS.
 */

/** @todo Ensure that every global init gets a free. */

#define _GNU_SOURCE

#ifdef _WIN32

#define WINVER 0x0501
#define SHUT_RDWR 2
#include <winsock2.h>
#include <winsock.h>

#else

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#endif

#include <unistd.h>
#include <gcrypt.h>
#include <glib.h>
#include <string.h>
#include <stdio.h>

#include "openvas_server.h"

/**
 * @todo This module nearly fulfils the requirements to be placed in the base
 * library (the gnutls dependency makes it a candidate for the net library).
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  serv"

/**
 * @brief Server address.
 */
struct sockaddr_in address;



static int server_attach_internal (int, gnutls_session_t *,
                                   const char *, int);
static int server_new_internal (unsigned int, const char *,
                                const gchar *,
                                const gchar *, const gchar *,
                                gnutls_session_t *,
                                gnutls_certificate_credentials_t *);



/* Connections. */

/**
 * @brief Close UNIX socket connection.
 *
 * @param[in]  client_connection  Client connection.
 *
 * @return 0 success, -1 error.
 */
static int
close_unix (openvas_connection_t *client_connection)
{
  /* Turn off blocking. */
  if (fcntl (client_connection->socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set server socket flag: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  if (shutdown (client_connection->socket, SHUT_RDWR) == -1)
    {
      if (errno == ENOTCONN)
        return 0;
      g_warning ("%s: failed to shutdown server socket: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  if (close (client_connection->socket) == -1)
    {
      g_warning ("%s: failed to close server socket: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  return 0;
}

/**
 * @brief Free connection.
 *
 * @param[in]  client_connection  Connection.
 */
void
openvas_connection_free (openvas_connection_t *client_connection)
{
  if (client_connection->tls)
    openvas_server_free (client_connection->socket,
                         client_connection->session,
                         client_connection->credentials);
  else
    close_unix (client_connection);
}


/* Certificate verification. */

/**
 * @brief Verify certificate.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 *
 * @return 0 on success, 1 on failure, -1 on error.
 */
int
openvas_server_verify (gnutls_session_t session)
{
  unsigned int status;
  int ret;

  ret = gnutls_certificate_verify_peers2 (session, &status);
  if (ret < 0)
    {
      g_warning ("%s: failed to verify peers: %s",
                 __FUNCTION__,
                 gnutls_strerror (ret));
      return -1;
    }

  if (status & GNUTLS_CERT_INVALID)
    g_warning ("%s: the certificate is not trusted", __FUNCTION__);

  if (status & GNUTLS_CERT_SIGNER_NOT_CA)
    g_warning ("%s: the certificate's issuer is not a CA", __FUNCTION__);

  if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
    g_warning ("%s: the certificate was signed using an insecure algorithm",
               __FUNCTION__);

  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    g_warning ("%s: the certificate hasn't got a known issuer", __FUNCTION__);

  if (status & GNUTLS_CERT_REVOKED)
    g_warning ("%s: the certificate has been revoked", __FUNCTION__);

  if (status & GNUTLS_CERT_EXPIRED)
    g_warning ("%s: the certificate has expired", __FUNCTION__);

  if (status & GNUTLS_CERT_NOT_ACTIVATED)
    g_warning ("%s: the certificate is not yet activated", __FUNCTION__);

  if (status)
    return 1;

  return 0;
}

/**
 * @brief Loads a file's data into gnutls_datum_t struct.
 *
 * @param[in]   file          File to load.
 * @param[out]  loaded_file   Destination to load file into.
 *
 * @return 0 if success, -1 if error.
 */
int
load_gnutls_file (const char *file, gnutls_datum_t *loaded_file)
{
  FILE *f = NULL;
  int64_t filelen;
  void *ptr;

  if (!(f = fopen (file, "r"))
      || fseek (f, 0, SEEK_END) != 0
      || (filelen = ftell (f)) < 0
      || fseek (f, 0, SEEK_SET) != 0
      || !(ptr = g_malloc0 ((size_t) filelen))
      || fread (ptr, 1, (size_t) filelen, f) < (size_t) filelen)
    {
      if (f)
        fclose (f);
      return -1;
    }

  loaded_file->data = ptr;
  loaded_file->size = filelen;
  fclose (f);
  return 0;
}

/**
 * @brief Unloads a gnutls_datum_t struct's data.
 *
 * @param[in]  data     Pointer to gnutls_datum_t struct to be unloaded.
 */
void
unload_gnutls_file(gnutls_datum_t *data)
{
  if (data)
    g_free (data->data);
}

static char *cert_pub_mem = NULL;
static char *cert_priv_mem = NULL;

static void
set_cert_pub_mem (const char *data)
{
  if (cert_pub_mem)
    g_free (cert_pub_mem);
  cert_pub_mem = g_strdup (data);
}

static void
set_cert_priv_mem (const char *data)
{
  if (cert_priv_mem)
    g_free (cert_priv_mem);
  cert_priv_mem = g_strdup (data);
}

static const char *
get_cert_priv_mem ()
{
  return cert_priv_mem;
}

static const char *
get_cert_pub_mem ()
{
  return cert_pub_mem;
}

static int
client_cert_callback (gnutls_session_t session,
                      const gnutls_datum_t * req_ca_rdn, int nreqs,
                      const gnutls_pk_algorithm_t * sign_algos,
                      int sign_algos_length, gnutls_retr2_st * st)
{
  int ret;
  gnutls_datum_t data;
  static gnutls_x509_crt_t crt;
  static gnutls_x509_privkey_t key;

  (void) session;
  (void) req_ca_rdn;
  (void) nreqs;
  (void) sign_algos;
  (void) sign_algos_length;
  data.data = (unsigned char *) g_strdup (get_cert_pub_mem ());
  data.size = strlen (get_cert_pub_mem ());
  gnutls_x509_crt_init (&crt);
  ret = gnutls_x509_crt_import (crt, &data, GNUTLS_X509_FMT_PEM);
  g_free (data.data);
  if (ret)
    return ret;
  st->cert.x509 = &crt;
  st->cert_type = GNUTLS_CRT_X509;
  st->ncerts = 1;

  data.data = (unsigned char *) g_strdup (get_cert_priv_mem ());
  data.size = strlen (get_cert_priv_mem ());
  gnutls_x509_privkey_init (&key);
  ret = gnutls_x509_privkey_import (key, &data, GNUTLS_X509_FMT_PEM);
  g_free (data.data);
  if (ret)
    return ret;
  st->key.x509 = key;
  st->key_type = GNUTLS_PRIVKEY_X509;
  return 0;
}

/**
 * @brief Connect to the server using a given host, port and cert.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  host      Host to connect to.
 * @param[in]  port      Port to connect to.
 * @param[in]  ca_mem    CA cert.
 * @param[in]  pub_mem   Public key.
 * @param[in]  priv_mem  Private key.
 * @param[in]  verify    Whether to verify.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_open_verify (gnutls_session_t *session, const char *host,
                            int port, const char *ca_mem,
                            const char *pub_mem, const char *priv_mem,
                            int verify)
{
  int ret;
  int server_socket;
  struct addrinfo address_hints;
  struct addrinfo *addresses, *address;
  gchar *port_string;
#ifdef _WIN32
  WSADATA wsaData;
#endif

  gnutls_certificate_credentials_t credentials;

  /** @todo Ensure that host and port have sane values. */
  /** @todo Improve logging. */
  /** @todo On success we are leaking the credentials.  We can't free
      them because the session only makes a shallow copy.  A
      solution would be to lookup already created credentials and
      reuse them.  */

  if (openvas_server_new_mem (GNUTLS_CLIENT, ca_mem, pub_mem, priv_mem, session,
                              &credentials))
    {
      g_warning ("Failed to create client TLS session.");
      return -1;
    }

  if (ca_mem && pub_mem && priv_mem)
    {
      set_cert_pub_mem (pub_mem);
      set_cert_priv_mem (priv_mem);

      gnutls_certificate_set_retrieve_function (credentials,
                                                client_cert_callback);
    }

  /* Create the port string. */

  port_string = g_strdup_printf ("%i", port);

  /* WSA Start for win32 */
#ifdef _WIN32
  if (WSAStartup (MAKEWORD (2, 2), &wsaData))
    {
      g_warning ("WSAStartup failed");
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      g_free (port_string);
      return -1;
    }
#endif

  /* Get all possible addresses. */

  memset (&address_hints, 0, sizeof (address_hints));
  address_hints.ai_family = AF_UNSPEC;  /* IPv4 or IPv6. */
  address_hints.ai_socktype = SOCK_STREAM;
#ifndef _WIN32
  address_hints.ai_flags = AI_NUMERICSERV;
#endif
  address_hints.ai_protocol = 0;

  if (getaddrinfo (host, port_string, &address_hints, &addresses))
    {
      g_free (port_string);
      g_warning ("Failed to get server addresses for %s: %s", host,
                 gai_strerror (errno));
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }
  g_free (port_string);

  /* Try to connect to each address in turn. */

  for (address = addresses; address; address = address->ai_next)
    {
      /* Make server socket. */

      if (address->ai_family == AF_INET6)
        server_socket = socket (PF_INET6, SOCK_STREAM, 0);
      else
        server_socket = socket (PF_INET, SOCK_STREAM, 0);
      if (server_socket == -1)
        {
          g_warning ("Failed to create server socket");
          freeaddrinfo (addresses);
          gnutls_deinit (*session);
          gnutls_certificate_free_credentials (credentials);
          return -1;
        }

      /** @todo Use openvas_server_connect. */

      /* Connect to server. */

      if (connect (server_socket, address->ai_addr, address->ai_addrlen) == -1)
        {
          close (server_socket);
          continue;
        }
      break;
    }

  freeaddrinfo (addresses);

  if (address == NULL)
    {
      g_warning ("Failed to connect to server");
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }

  g_debug ("   Connected to server '%s' port %d.", host, port);

  /* Complete setup of server session. */
  ret = server_attach_internal (server_socket, session, host, port);
  if (ret)
    {
      if (ret == -2)
        {
          close (server_socket);
          gnutls_deinit (*session);
          gnutls_certificate_free_credentials (credentials);
        }
      return -1;
    }
  if (verify && openvas_server_verify (*session))
    return -1;

  return server_socket;
}

/**
 * @brief Connect to the server using a given host, port and cert.
 *
 * Verify if all cert args are given.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  host      Host to connect to.
 * @param[in]  port      Port to connect to.
 * @param[in]  ca_mem    CA cert.
 * @param[in]  pub_mem   Public key.
 * @param[in]  priv_mem  Private key.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_open_with_cert (gnutls_session_t *session, const char *host,
                               int port, const char *ca_mem,
                               const char *pub_mem, const char *priv_mem)
{
  return openvas_server_open_verify (session, host, port, ca_mem, pub_mem,
                                     priv_mem, ca_mem && pub_mem && priv_mem);
}

/**
 * @brief Connect to the server using a given host and port.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  host     Host to connect to.
 * @param[in]  port     Port to connect to.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_open (gnutls_session_t * session, const char *host, int port)
{
  return openvas_server_open_with_cert (session, host, port, NULL, NULL, NULL);
}

/**
 * @brief Close a server connection and its socket.
 *
 * @param[in]  socket   Socket connected to server (from \ref connect_to_server).
 * @param[in]  session  GNUTLS session with server.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_close (int socket, gnutls_session_t session)
{
  return openvas_server_free (socket, session, NULL);
}

/**
 * @brief Close a server connection and its socket.
 *
 * @param[in]  connection  Connection.
 *
 * @return 0 on success, -1 on error.
 */
void
openvas_connection_close (openvas_connection_t *connection)
{
  openvas_connection_free (connection);
}

/**
 * @brief Connect to a server.
 *
 * @param[in]  server_socket   Socket to connect to server.
 * @param[in]  server_address  Server address.
 * @param[in]  server_session  Session to connect to server.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_connect (int server_socket, struct sockaddr_in *server_address,
                        gnutls_session_t * server_session)
{
  int ret;

  if (connect (server_socket, (struct sockaddr *) server_address,
               sizeof (struct sockaddr_in)) == -1)
    {
      g_warning ("%s: failed to connect to server: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  g_debug ("   Connected to server on socket %i.\n", server_socket);

  ret = openvas_server_attach (server_socket, server_session);
  if (ret < 0)
    return ret;
  return openvas_server_verify (*server_session);
}

/**
 * @brief Attach a socket to a session, and shake hands with the peer.
 *
 * @param[in]  socket   Socket.
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  host     NULL or the name of the host for diagnostics
 * @param[in]  port     Port number for diagnostics; only used
 *                      if \a host is not NULL
 *
 * @return 0 on success, -1 on general error, -2 if the TLS handshake failed.
 */
static int
server_attach_internal (int socket, gnutls_session_t * session,
                        const char *host, int port)
{
  unsigned int retries;
#ifndef _WIN32
  struct sigaction new_action, original_action;
#endif

  gnutls_transport_set_ptr (*session,
                            (gnutls_transport_ptr_t) GSIZE_TO_POINTER (socket));

#ifndef _WIN32
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;
#endif

  retries = 0;
  while (1)
    {
      int ret = gnutls_handshake (*session);
      if (ret >= 0)
        break;
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        {
          if (retries > 10)
            usleep (MIN ((retries - 10) * 10000, 5000000));
          retries++;
          continue;
        }
      if (host)
        g_debug ("Failed to shake hands with server '%s' port %d: %s",
                 host, port, gnutls_strerror (ret));
      else
        g_debug ("Failed to shake hands with peer: %s",
                 gnutls_strerror (ret));
      if (shutdown (socket, SHUT_RDWR) == -1)
        g_debug ("Failed to shutdown server socket");
#ifndef _WIN32
      sigaction (SIGPIPE, &original_action, NULL);
#endif
      return -2;
    }
  if (host)
    g_debug ("   Shook hands with server '%s' port %d.", host, port);
  else
    g_debug ("   Shook hands with peer.");

#ifndef _WIN32
  if (sigaction (SIGPIPE, &original_action, NULL))
    return -1;
#endif

  return 0;
}

/**
 * @brief Attach a socket to a session, and shake hands with the peer.
 *
 * @param[in]  socket   Socket.
 * @param[in]  session  Pointer to GNUTLS session.
 *                      FIXME: Why is this a pointer to a session?
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_attach (int socket, gnutls_session_t * session)
{
  int ret;

  ret = server_attach_internal (socket, session, NULL, 0);
  return ret? -1 : 0;
}

/**
 * @brief Send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  fmt      Format of string to send.
 * @param[in]  ap       Args for fmt.
 * @param[in]  quiet    Whether to log debug and info messages.  Useful for
 *                      hiding passwords.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
static int
openvas_server_vsendf_internal (gnutls_session_t *session, const char *fmt,
                                va_list ap, int quiet)
{
#ifndef _WIN32
  struct sigaction new_action, original_action;
#endif
  char *sref, *string;
  int rc = 0, left;

#ifndef _WIN32
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;
#endif

  left = vasprintf (&string, fmt, ap);
  if (left == -1)
    string = NULL;

  sref = string;
  while (left > 0)
    {
      ssize_t count;

      if (quiet == 0)
        g_debug ("   send %d from %.*s[...]",
                 left, left < 30 ? left : 30, string);
      count = gnutls_record_send (*session, string, left);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              if (quiet == 0)
                g_message ("   %s rehandshake", __FUNCTION__);
              continue;
            }
          g_warning ("Failed to write to server: %s", gnutls_strerror (count));

#ifndef _WIN32
          sigaction (SIGPIPE, &original_action, NULL);
#endif

          rc = -1;
          goto out;
        }
      if (count == 0)
        {
          /* Server closed connection. */
          if (quiet == 0)
            g_debug ("=  server closed");

#ifndef _WIN32
          sigaction (SIGPIPE, &original_action, NULL);
#endif

          rc = 1;
          goto out;
        }
      if (quiet == 0)
        g_debug ("=> %.*s", (int) count, string);
      string += count;
      left -= count;
    }
  if (quiet == 0)
    g_debug ("=> done");

#ifndef _WIN32
  sigaction (SIGPIPE, &original_action, NULL);
#endif

out:
  g_free (sref);
  return rc;
}

/**
 * @brief Send a string to the server.
 *
 * @param[in]  socket   Socket.
 * @param[in]  fmt      Format of string to send.
 * @param[in]  ap       Args for fmt.
 * @param[in]  quiet    Whether to log debug and info messages.  Useful for
 *                      hiding passwords.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
static int
unix_vsendf_internal (int socket, const char *fmt, va_list ap, int quiet)
{
#ifndef _WIN32
  struct sigaction new_action, original_action;
#endif
  char *string_start, *string;
  int rc = 0, left;

#ifndef _WIN32
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    // FIX warning
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    // FIX warning
    return -1;
#endif

  left = vasprintf (&string, fmt, ap);
  if (left == -1)
    string = NULL;

  string_start = string;
  while (left > 0)
    {
      ssize_t count;

      if (quiet == 0)
        g_debug ("   send %d from %.*s[...]",
                 left, left < 30 ? left : 30, string);
      count = write (socket, string, left);
      if (count < 0)
        {
          if (errno == EINTR || errno == EAGAIN)
            continue;
          g_warning ("Failed to write to server: %s", strerror (errno));

#ifndef _WIN32
          sigaction (SIGPIPE, &original_action, NULL);
#endif

          rc = -1;
          goto out;
        }
      if (quiet == 0)
        g_debug ("=> %.*s", (int) count, string);

      string += count;
      left -= count;
    }
  if (quiet == 0)
    g_debug ("=> done");

#ifndef _WIN32
  sigaction (SIGPIPE, &original_action, NULL);
#endif

out:
  g_free (string_start);
  return rc;
}

/**
 * @brief Send a string to the connection.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  fmt      Format of string to send.
 * @param[in]  ap       Args for fmt.
 * @param[in]  quiet    Whether to log debug and info messages.  Useful for
 *                      hiding passwords.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
static int
openvas_connection_vsendf_internal (openvas_connection_t *connection,
                                    const char *fmt, va_list ap, int quiet)
{
  if (connection->tls)
    return openvas_server_vsendf_internal (&connection->session, fmt, ap, quiet);
  return unix_vsendf_internal (connection->socket, fmt, ap, quiet);
}

/**
 * @brief Send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  fmt      Format of string to send.
 * @param[in]  ap       Args for fmt.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
int
openvas_server_vsendf (gnutls_session_t *session, const char *fmt, va_list ap)
{
  return openvas_server_vsendf_internal (session, fmt, ap, 0);
}

/**
 * @brief Send a string to the server.
 *
 * @param[in]  connection  Connection.
 * @param[in]  fmt         Format of string to send.
 * @param[in]  ap          Args for fmt.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
int
openvas_connection_vsendf (openvas_connection_t *connection, const char *fmt,
                           va_list ap)
{
  return openvas_connection_vsendf_internal (connection, fmt, ap, 0);
}

/**
 * @brief Send a string to the server, refraining from logging besides warnings.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  fmt      Format of string to send.
 * @param[in]  ap       Args for fmt.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
int
openvas_server_vsendf_quiet (gnutls_session_t *session, const char *fmt,
                             va_list ap)
{
  return openvas_server_vsendf_internal (session, fmt, ap, 1);
}

/**
 * @brief Send a string to the server, refraining from logging besides warnings.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  fmt      Format of string to send.
 * @param[in]  ap       Args for fmt.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
int
openvas_connection_vsendf_quiet (openvas_connection_t *connection,
                                 const char *fmt,
                                 va_list ap)
{
  return openvas_connection_vsendf_internal (connection, fmt, ap, 1);
}

/**
 * @brief Format and send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_sendf (gnutls_session_t * session, const char *format, ...)
{
  va_list ap;
  int rc;

  va_start (ap, format);
  rc = openvas_server_vsendf (session, format, ap);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_connection_sendf (openvas_connection_t *connection,
                          const char *format,
                          ...)
{
  va_list ap;
  int rc;

  va_start (ap, format);
  rc = openvas_connection_vsendf (connection, format, ap);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_sendf_quiet (gnutls_session_t * session, const char *format, ...)
{
  va_list ap;
  int rc;

  va_start (ap, format);
  rc = openvas_server_vsendf_quiet (session, format, ap);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_connection_sendf_quiet (openvas_connection_t *connection,
                                const char *format,
                                ...)
{
  va_list ap;
  int rc;

  va_start (ap, format);
  rc = openvas_connection_vsendf_quiet (connection, format, ap);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send an XML string to the server.
 *
 * Escape XML in string and character args.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_sendf_xml (gnutls_session_t * session, const char *format, ...)
{
  va_list ap;
  gchar *msg;
  int rc;

  va_start (ap, format);
  msg = g_markup_vprintf_escaped (format, ap);
  rc = openvas_server_sendf (session, "%s", msg);
  g_free (msg);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send an XML string to the server.
 *
 * Escape XML in string and character args.
 *
 * @param[in]  connection  Connection.
 * @param[in]  format      printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_connection_sendf_xml (openvas_connection_t *connection,
                              const char *format, ...)
{
  va_list ap;
  gchar *msg;
  int rc;

  va_start (ap, format);
  msg = g_markup_vprintf_escaped (format, ap);
  rc = openvas_connection_sendf (connection, "%s", msg);
  g_free (msg);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send an XML string to the server.
 *
 * Escape XML in string and character args.
 *
 * Quiet version, only logs warnings.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_sendf_xml_quiet (gnutls_session_t * session,
                                const char *format, ...)
{
  va_list ap;
  gchar *msg;
  int rc;

  va_start (ap, format);
  msg = g_markup_vprintf_escaped (format, ap);
  rc = openvas_server_sendf_quiet (session, "%s", msg);
  g_free (msg);
  va_end (ap);
  return rc;
}

/**
 * @brief Format and send an XML string to the server.
 *
 * Escape XML in string and character args.
 *
 * Quiet version, only logs warnings.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  format   printf-style format string for message.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_connection_sendf_xml_quiet (openvas_connection_t *connection,
                                    const char *format,
                                    ...)
{
  va_list ap;
  gchar *msg;
  int rc;

  va_start (ap, format);
  msg = g_markup_vprintf_escaped (format, ap);
  rc = openvas_connection_sendf_quiet (connection, "%s", msg);
  g_free (msg);
  va_end (ap);
  return rc;
}

static int
server_new_gnutls_init (gnutls_certificate_credentials_t *server_credentials)
{
  /* Turn off use of /dev/random, as this can block. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  /* Initialize security library. */
  if (gnutls_global_init ())
    {
      g_warning ("Failed to initialize GNUTLS.");
      return -1;
    }
  /* Setup server session. */
  if (gnutls_certificate_allocate_credentials (server_credentials))
    {
      g_warning ("%s: failed to allocate server credentials\n", __FUNCTION__);
      return -1;
    }
  return 0;
}

static int
server_new_gnutls_set (unsigned int end_type, const char *priority,
                       gnutls_session_t *server_session,
                       gnutls_certificate_credentials_t *server_credentials)
{
  int err_gnutls;

  if (gnutls_init (server_session, end_type))
    {
      g_warning ("%s: failed to initialise server session\n", __FUNCTION__);
      return -1;
    }

  /* Depending on gnutls version different priority strings are
     possible. At least from 3.0 this is an option:
     "NONE:+VERS-TLS1.0:+CIPHER-ALL:+COMP-ALL:+RSA:+DHE-RSA:+DHE-DSS:+MAC-ALL"
     But in fact this function is only for OpenVAS internal
     purposes, not for scanning abilities. So, the conservative "NORMAL"
     is chosen.
  */

  if ((err_gnutls = gnutls_priority_set_direct (*server_session,
                                                priority ? priority : "NORMAL",
                                                NULL)))
    {
      g_warning ("%s: failed to set tls priorities: %s\n", __FUNCTION__,
                 gnutls_strerror (err_gnutls));
      gnutls_deinit (*server_session);
      return -1;
    }

  if (gnutls_credentials_set
      (*server_session, GNUTLS_CRD_CERTIFICATE, *server_credentials))
    {
      g_warning ("%s: failed to set server credentials\n", __FUNCTION__);
      gnutls_deinit (*server_session);
      return -1;
    }

  if (end_type == GNUTLS_SERVER)
    gnutls_certificate_server_set_request (*server_session,
                                           GNUTLS_CERT_REQUEST);
  return 0;
}

/**
 * @brief Make a session for connecting to a server.
 *
 * @param[in]   end_type            Connection end type (GNUTLS_SERVER or
 *                                  GNUTLS_CLIENT).
 * @param[in]   priority            Custom priority string or NULL.
 * @param[in]   ca_cert_file        Certificate authority file.
 * @param[in]   cert_file           Certificate file.
 * @param[in]   key_file            Key file.
 * @param[out]  server_session      The session with the server.
 * @param[out]  server_credentials  Server credentials.
 *
 * @return 0 on success, -1 on error.
 */
static int
server_new_internal (unsigned int end_type, const char *priority,
                     const gchar *ca_cert_file,
                     const gchar *cert_file, const gchar *key_file,
                     gnutls_session_t *server_session,
                     gnutls_certificate_credentials_t *server_credentials)
{
  if (server_new_gnutls_init (server_credentials))
    return -1;

  if (cert_file && key_file
      &&
      (gnutls_certificate_set_x509_key_file
       (*server_credentials, cert_file, key_file, GNUTLS_X509_FMT_PEM) < 0))
    {
      g_warning ("%s: failed to set credentials key file\n", __FUNCTION__);
      g_warning ("%s:   cert file: %s\n", __FUNCTION__, cert_file);
      g_warning ("%s:   key file : %s\n", __FUNCTION__, key_file);
      gnutls_certificate_free_credentials (*server_credentials);
      return -1;
    }

  if (ca_cert_file
      &&
      (gnutls_certificate_set_x509_trust_file
       (*server_credentials, ca_cert_file, GNUTLS_X509_FMT_PEM) < 0))
    {
      g_warning ("%s: failed to set credentials trust file: %s\n", __FUNCTION__,
                 ca_cert_file);
      gnutls_certificate_free_credentials (*server_credentials);
      return -1;
    }

  if (server_new_gnutls_set (end_type, priority, server_session,
                             server_credentials))
    {
      gnutls_certificate_free_credentials (*server_credentials);
      return -1;
    }

  return 0;
}

/**
 * @brief Make a session for connecting to a server.
 *
 * @param[in]   end_type            Connection end type (GNUTLS_SERVER or
 *                                  GNUTLS_CLIENT).
 * @param[in]   ca_cert_file        Certificate authority file.
 * @param[in]   cert_file           Certificate file.
 * @param[in]   key_file            Key file.
 * @param[out]  server_session      The session with the server.
 * @param[out]  server_credentials  Server credentials.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_new (unsigned int end_type,
                    gchar * ca_cert_file,
                    gchar * cert_file, gchar * key_file,
                    gnutls_session_t * server_session,
                    gnutls_certificate_credentials_t * server_credentials)
{
  return server_new_internal (end_type, NULL,
                              ca_cert_file, cert_file, key_file,
                              server_session, server_credentials);
}

/**
 * @brief Make a session for connecting to a server, with certificates stored
 *        in memory.
 *
 * @param[in]   end_type    Connecton end type: GNUTLS_SERVER or GNUTLS_CLIENT.
 * @param[in]   ca_cert     Certificate authority public key.
 * @param[in]   pub_key     Public key.
 * @param[in]   priv_key    Private key.
 * @param[out]  session     The session with the server.
 * @param[out]  credentials Server credentials.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_new_mem (unsigned int end_type, const char *ca_cert,
                        const char *pub_key, const char *priv_key,
                        gnutls_session_t *session,
                        gnutls_certificate_credentials_t *credentials)
{
  if (server_new_gnutls_init (credentials))
    return -1;

  if (pub_key && priv_key)
    {
      int ret;
      gnutls_datum_t pub, priv;

      pub.data = (void *) pub_key;
      pub.size = strlen (pub_key);
      priv.data = (void *) priv_key;
      priv.size = strlen (priv_key);

      ret = gnutls_certificate_set_x509_key_mem (*credentials, &pub, &priv,
                                                 GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          g_warning ("%s: %s\n", __FUNCTION__, gnutls_strerror (ret));
          return -1;
        }
    }

  if (ca_cert)
    {
      int ret;
      gnutls_datum_t data;

      data.data = (void *) ca_cert;
      data.size = strlen (ca_cert);
      ret = gnutls_certificate_set_x509_trust_mem (*credentials, &data,
                                                   GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          g_warning ("%s: %s\n", __FUNCTION__, gnutls_strerror (ret));
          gnutls_certificate_free_credentials (*credentials);
          return -1;
        }
    }

  if (server_new_gnutls_set (end_type, NULL, session, credentials))
    {
      gnutls_certificate_free_credentials (*credentials);
      return -1;
    }

  return 0;
}

/**
 * @brief Set a gnutls session's  Diffie-Hellman parameters.
 *
 * @param[in]   creds           GnuTLS credentials.
 * @param[in]   dhparams_file   Path to PEM file containing the DH parameters.
 *
 * @return 0 on success, -1 on error.
 */
int
set_gnutls_dhparams (gnutls_certificate_credentials_t creds,
                     const char *dhparams_file)
{
  int ret;
  gnutls_datum_t data;

  if (!creds || !dhparams_file)
    return -1;

  if (load_gnutls_file (dhparams_file, &data))
    return -1;
  gnutls_dh_params_t params = g_malloc0 (sizeof (gnutls_dh_params_t));
  ret = gnutls_dh_params_import_pkcs3 (params, &data, GNUTLS_X509_FMT_PEM);
  unload_gnutls_file (&data);
  if (ret)
    return -1;
  else
    gnutls_certificate_set_dh_params (creds, params);
  return 0;
}

/**
 * @brief Cleanup a server session.
 *
 * This shuts down the TLS session, closes the socket and releases the
 * TLS resources.
 *
 * @param[in]  server_socket       The socket connected to the server.
 * @param[in]  server_session      The session with the server.
 * @param[in]  server_credentials  Credentials or NULL.
 *
 * @return 0 success, -1 error.
 */
int
openvas_server_free (int server_socket, gnutls_session_t server_session,
                     gnutls_certificate_credentials_t server_credentials)
{
#ifndef _WIN32
  struct sigaction new_action, original_action;
#endif

#if 0
  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (server_socket, F_SETFL, 0L) == -1)
    {
      g_warning ("%s: failed to set server socket flag: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
    }
#endif
#if 1
  /* Turn off blocking. */
  // FIX get flags first
#ifndef _WIN32
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set server socket flag: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
    }
#endif
#endif

#ifndef _WIN32
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;
#endif

  while (1)
    {
      int ret = gnutls_bye (server_session, GNUTLS_SHUT_WR);
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        {
          continue;
        }
      if (ret)
        {
          g_debug ("   Failed to gnutls_bye: %s\n",
                   gnutls_strerror ((int) ret));
          /* Carry on successfully anyway, as this often fails, perhaps
           * because the server is closing the connection first. */
          break;
        }
      break;
    }

  /* The former separate code in openvas_server_close and here
     differed in the order the TLS session and socket was closed.  The
     way we do it here seems to be the right thing but for full
     backward compatibility we do it for calls from
     openvas_server_close in the old way.  We can distinguish the two
     modes by the existence of server_credentials.  */
  if (server_credentials)
    {
#ifndef _WIN32
      if (sigaction (SIGPIPE, &original_action, NULL))
        return -1;

      if (shutdown (server_socket, SHUT_RDWR) == -1)
        {
          if (errno == ENOTCONN)
            return 0;
          g_warning ("%s: failed to shutdown server socket: %s\n", __FUNCTION__,
                     strerror (errno));
          return -1;
        }
#endif

      if (close (server_socket) == -1)
        {
          g_warning ("%s: failed to close server socket: %s\n", __FUNCTION__,
                     strerror (errno));
          return -1;
        }
      gnutls_deinit (server_session);
      gnutls_certificate_free_credentials (server_credentials);
    }
  else
    {
      gnutls_deinit (server_session);
#ifndef _WIN32
      if (sigaction (SIGPIPE, &original_action, NULL))
        return -1;
#endif
      close (server_socket);
    }

  gnutls_global_deinit ();

  return 0;
}
