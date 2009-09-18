/**
 * GnuTLS based functions for communication with an OpenVAS server.
 * Copyright (C) 2009  Greenbone Networks GmbH
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 * Michael Wiegand <michael.wiegand@greenbone.net>
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

#include <glib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "openvas_server.h"

/**
 * @todo This module nearly fulfils the reqirements to be placed in the base
 * library (the gnutls dependency makes it a candidate for the net library).
 */

/**
 * @brief Server address.
 */
struct sockaddr_in address;

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
openvas_server_open (gnutls_session_t * session,
                     const char *host, int port)
{
  /** @todo Ensure that host and port have sane values. */
  /** @todo Improve logging.*/

  /* Initialize security library. */

  int ret = gnutls_global_init();
  if (ret < 0)
    {
      g_message ("Failed to initialize GNUTLS.");
      return -1;
    }

  /* Setup address. */

  address.sin_family = AF_INET;

  address.sin_port = htons (port);

  if (!inet_aton (host, &address.sin_addr))
    {
      g_message ("Failed to create server address %s.",
                 host);
      return -1;
    }

  g_message ("Set to connect to address %s port %i",
             host,
             ntohs (address.sin_port));

  /* Make server socket. */

  int server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      g_message ("Failed to create server socket");
      return -1;
    }

  /* Setup server session. */

  gnutls_certificate_credentials_t credentials;
  if (gnutls_certificate_allocate_credentials (&credentials))
    {
      g_message ("Failed to allocate server credentials.");
      goto close_fail;
    }

  if (gnutls_init (session, GNUTLS_CLIENT))
    {
      g_message ("Failed to initialise server session.");
      goto server_free_fail;
    }

  if (gnutls_set_default_priority (*session))
    {
      g_message ("Failed to set server session priority.");
      goto server_fail;
    }

  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  if (gnutls_kx_set_priority (*session, kx_priority))
    {
      g_message ("Failed to set server key exchange priority.");
      goto server_fail;
    }

  if (gnutls_credentials_set (*session,
                              GNUTLS_CRD_CERTIFICATE,
                              credentials))
    {
      g_message ("Failed to set server credentials.");
      goto server_fail;
    }

  /* Connect to server. */

  if (connect (server_socket,
               (struct sockaddr *) &address,
               sizeof (struct sockaddr_in))
      == -1)
    {
      g_message ("Failed to connect to server");
      return -1;
    }

  g_message ("connected to server");

  /* Complete setup of server session. */

  gnutls_transport_set_ptr (*session,
                            (gnutls_transport_ptr_t) server_socket);

  while (1)
    {
      int ret = gnutls_handshake (*session);
      if (ret >= 0)
        break;
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        continue;
      g_message ("Failed to shake hands with server.");
      gnutls_perror (ret);
      if (shutdown (server_socket, SHUT_RDWR) == -1)
        g_message ("Failed to shutdown server socket");
      goto server_fail;
    }
  g_message ("Shook hands with server.");

  return server_socket;

 server_fail:
  gnutls_deinit (*session);

 server_free_fail:
  gnutls_certificate_free_credentials (credentials);

 close_fail:
  close (server_socket);

  return -1;
}

/**
 * @brief Close a server connection.
 *
 * @param[in]  socket   Socket connected to server (from \ref connect_to_server).
 * @param[in]  session  GNUTLS session with server.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_close (int socket, gnutls_session_t session)
{
  /* Turn off blocking. */
  if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1) return -1;

  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close (socket);
  return 0;
}

/** @todo Use in openvas_server_open. */
/**
 * @brief Connect to a server.
 *
 * @param[in]  server_socket   Socket to connect to server.
 * @param[in]  server_address  Server address.
 * @param[in]  server_session  Session to connect to server.
 * @param[in]  interrupted     0 if first connect attempt, else retrying after
 *                             an interrupted connect.
 *
 * @return 0 on success, -1 on error, -2 on connect interrupt.
 */
int
openvas_server_connect (int server_socket,
                        struct sockaddr_in* server_address,
                        gnutls_session_t* server_session,
                        gboolean interrupted)
{
  int ret;
  socklen_t ret_len = sizeof (ret);
  if (interrupted)
    {
      if (getsockopt (server_socket, SOL_SOCKET, SO_ERROR, &ret, &ret_len)
          == -1)
        {
          g_warning ("%s: failed to get socket option: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }
      if (ret_len != (socklen_t) sizeof (ret))
        {
          g_warning ("%s: weird option length from getsockopt: %i\n",
                     __FUNCTION__,
                     /* socklen_t is an int, according to getsockopt(2). */
                     (int) ret_len);
          return -1;
        }
      if (ret)
        {
          if (ret == EINPROGRESS) return -2;
          g_warning ("%s: failed to connect to server (interrupted): %s\n",
                     __FUNCTION__,
                     strerror (ret));
          return -1;
        }
    }
  else if (connect (server_socket,
                    (struct sockaddr *) server_address,
                    sizeof (struct sockaddr_in))
           == -1)
    {
      if (errno == EINPROGRESS) return -2;
      g_warning ("%s: failed to connect to server: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  g_debug ("   Connected to server on socket %i.\n", server_socket);

  /* Complete setup of server session. */

  gnutls_transport_set_ptr (*server_session,
                            (gnutls_transport_ptr_t) server_socket);

  while (1)
    {
      ret = gnutls_handshake (*server_session);
      if (ret >= 0)
        break;
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        continue;
      g_warning ("%s: failed to shake hands with server: %s\n",
                 __FUNCTION__,
                 gnutls_strerror (ret));
      if (shutdown (server_socket, SHUT_RDWR) == -1)
        g_message ("   Failed to shutdown server socket: %s\n",
                   strerror (errno));
      return -1;
    }

  return 0;
}

/**
 * @brief Send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  string   String to send.
 *
 * @return 0 on success, 1 if server closed connection, -1 on error.
 */
int
openvas_server_send (gnutls_session_t* session, const char* string)
{
  size_t left = strlen (string);
  while (left)
    {
      ssize_t count;
      g_message ("send %i from %.*s[...]", left, left < 30 ? left : 30, string);
      count = gnutls_record_send (*session, string, left);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              g_message ("send_to_server rehandshake");
              continue;
            }
          g_message ("Failed to write to server.");
          gnutls_perror (count);
          return -1;
        }
      if (count == 0)
        {
          /* Server closed connection. */
          g_message ("=  server closed\n");
          return 1;
        }
      g_message ("=> %.*s", count, string);
      string += count;
      left -= count;
    }
  g_message ("=> done");

  return 0;
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
openvas_server_sendf (gnutls_session_t* session, const char* format, ...)
{
  va_list args;
  va_start (args, format);
  gchar* msg = g_strdup_vprintf (format, args);
  int ret = openvas_server_send (session, msg);
  g_free (msg);
  va_end (args);
  return ret;
}

/**
 * @brief Make a session for connecting to a server.
 *
 * @param[out]  server_socket       The socket connected to the server.
 * @param[out]  server_session      The session with the server.
 * @param[out]  server_credentials  Credentials.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_session_new (int server_socket,
                            gnutls_session_t* server_session,
                            gnutls_certificate_credentials_t*
                            server_credentials)
{
  /* Setup server session. */

  // FIX static vars?
  const int protocol_priority[] = { GNUTLS_TLS1,
                                    0 };
  const int cipher_priority[] = { GNUTLS_CIPHER_AES_128_CBC,
                                  GNUTLS_CIPHER_3DES_CBC,
                                  GNUTLS_CIPHER_AES_256_CBC,
                                  GNUTLS_CIPHER_ARCFOUR_128,
                                  0 };
  const int comp_priority[] = { GNUTLS_COMP_ZLIB,
                                GNUTLS_COMP_NULL,
                                0 };
  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  const int mac_priority[] = { GNUTLS_MAC_SHA1,
                               GNUTLS_MAC_MD5,
                               0 };

  if (gnutls_certificate_allocate_credentials (server_credentials))
    {
      g_warning ("%s: failed to allocate server credentials\n", __FUNCTION__);
      goto close_fail;
    }

  if (gnutls_init (server_session, GNUTLS_CLIENT))
    {
      g_warning ("%s: failed to initialise server session\n", __FUNCTION__);
      goto server_free_fail;
    }

  if (gnutls_protocol_set_priority (*server_session, protocol_priority))
    {
      g_warning ("%s: failed to set protocol priority\n", __FUNCTION__);
      goto server_fail;
    }

  if (gnutls_cipher_set_priority (*server_session, cipher_priority))
    {
      g_warning ("%s: failed to set cipher priority\n", __FUNCTION__);
      goto server_fail;
    }

  if (gnutls_compression_set_priority (*server_session, comp_priority))
    {
      g_warning ("%s: failed to set compression priority\n", __FUNCTION__);
      goto server_fail;
    }

  if (gnutls_kx_set_priority (*server_session, kx_priority))
    {
      g_warning ("%s: failed to set server key exchange priority\n",
                 __FUNCTION__);
      goto server_fail;
    }

  if (gnutls_mac_set_priority (*server_session, mac_priority))
    {
      g_warning ("%s: failed to set mac priority\n", __FUNCTION__);
      goto server_fail;
    }

  if (gnutls_credentials_set (*server_session,
                              GNUTLS_CRD_CERTIFICATE,
                              *server_credentials))
    {
      g_warning ("%s: failed to set server credentials\n", __FUNCTION__);
      goto server_fail;
    }

#if 0
  // FIX admin also had this

  /* request client certificate if any.
   */
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

  gnutls_dh_set_prime_bits (session, DH_BITS);
#endif

  // FIX get flags first
  // FIX after read_protocol
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set server socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      goto fail;
    }

  return 0;

 fail:
  (void) gnutls_bye (*server_session, GNUTLS_SHUT_RDWR);
 server_fail:
  (void) gnutls_deinit (*server_session);

 server_free_fail:
  gnutls_certificate_free_credentials (*server_credentials);

 close_fail:
  (void) close (server_socket);

  return -1;
}

/**
 * @brief Cleanup a server session.
 *
 * @param[in]  server_socket       The socket connected to the server.
 * @param[in]  server_session      The session with the server.
 * @param[in]  server_credentials  Credentials.
 *
 * @return 0 success, -1 error.
 */
int
openvas_server_session_free (int server_socket,
                             gnutls_session_t server_session,
                             gnutls_certificate_credentials_t
                             server_credentials)
{
  int count;

#if 0
  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (server_socket, F_SETFL, 0L) == -1)
    {
      g_warning ("%s: failed to set server socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
#endif
#if 1
  /* Turn off blocking. */
  // FIX get flags first
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set server socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
#endif

  count = 100;
  while (count)
    {
      int ret = gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        {
          count--;
          continue;
        }
      if (ret)
        {
          g_message ("   Failed to gnutls_bye: %s\n",
                     gnutls_strerror ((int) ret));
          /* Carry on successfully anyway, as this often fails, perhaps
           * because the server is closing the connection first. */
          break;
        }
      break;
    }
  if (count == 0) g_message ("   Gave up trying to gnutls_bye\n");

  if (shutdown (server_socket, SHUT_RDWR) == -1)
    {
      if (errno == ENOTCONN) return 0;
      g_warning ("%s: failed to shutdown server socket: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  if (close (server_socket) == -1)
    {
      g_warning ("%s: failed to close server socket: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  gnutls_deinit (server_session);

  gnutls_certificate_free_credentials (server_credentials);

  return 0;
}
