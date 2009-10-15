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

/** @todo Ensure that every global init gets a free. */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <glib.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

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
  int server_socket;
  struct addrinfo address_hints;
  struct addrinfo *addresses, *address;
  gchar *port_string;
  struct sigaction new_action, original_action;

  /** @todo Ensure that host and port have sane values. */
  /** @todo Improve logging. */

  /* Turn off use of /dev/random, as this can block. */

  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  /* Initialize security library. */

  int ret = gnutls_global_init();
  if (ret < 0)
    {
      g_message ("Failed to initialize GNUTLS.");
      return -1;
    }

  /* Setup server session. */

  /** @todo Use openvas_server_new. */

  gnutls_certificate_credentials_t credentials;
  if (gnutls_certificate_allocate_credentials (&credentials))
    {
      g_message ("Failed to allocate server credentials.");
      return -1;
    }

  // FIX always a client?
  if (gnutls_init (session, GNUTLS_CLIENT))
    {
      g_message ("Failed to initialise server session.");
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }

  if (gnutls_set_default_priority (*session))
    {
      g_message ("Failed to set server session priority.");
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }

  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  if (gnutls_kx_set_priority (*session, kx_priority))
    {
      g_message ("Failed to set server key exchange priority.");
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }

  if (gnutls_credentials_set (*session,
                              GNUTLS_CRD_CERTIFICATE,
                              credentials))
    {
      g_message ("Failed to set server credentials.");
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }

  /* Create the port string. */

  port_string = g_strdup_printf ("%i", port);

  /* Get all possible addresses. */

  memset (&address_hints, 0, sizeof (address_hints));
  address_hints.ai_family = AF_UNSPEC;     /* IPv4 or IPv6. */
  address_hints.ai_socktype = SOCK_STREAM;
  address_hints.ai_flags = AI_NUMERICSERV;
  address_hints.ai_protocol = 0;

  if (getaddrinfo (host, port_string, &address_hints, &addresses))
    {
      g_free (port_string);
      g_message ("Failed to get server addresses for %s: %s",
                 host,
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

      server_socket = socket (PF_INET, SOCK_STREAM, 0);
      if (server_socket == -1)
        {
          g_message ("Failed to create server socket");
          freeaddrinfo (addresses);
          gnutls_deinit (*session);
          gnutls_certificate_free_credentials (credentials);
          return -1;
        }

      /** @todo Use openvas_server_connect. */

      /* Connect to server. */

      if (connect (server_socket, address->ai_addr, address->ai_addrlen)
          == -1)
        {
          close (server_socket);
          continue;
        }
      break;
    }

  freeaddrinfo (addresses);

  if (address == NULL)
    {
      g_message ("Failed to connect to server");
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      return -1;
    }

  g_message ("   Connected to server.");

  /* Complete setup of server session. */

  gnutls_transport_set_ptr (*session,
                            (gnutls_transport_ptr_t) server_socket);

  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

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
      close (server_socket);
      gnutls_deinit (*session);
      gnutls_certificate_free_credentials (credentials);
      sigaction (SIGPIPE, &original_action, NULL);
      return -1;
    }
  g_message ("   Shook hands with server.");

  if (sigaction (SIGPIPE, &original_action, NULL)) return -1;

  return server_socket;
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
  struct sigaction new_action, original_action;

  /* Turn off blocking. */
  if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1) return -1;

  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

  gnutls_bye (session, GNUTLS_SHUT_RDWR);

  if (sigaction (SIGPIPE, &original_action, NULL)) return -1;

  close (socket);
  gnutls_global_deinit ();
  return 0;
}

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
  struct sigaction new_action, original_action;

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

  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

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
      sigaction (SIGPIPE, &original_action, NULL);
      return -1;
    }

  if (sigaction (SIGPIPE, &original_action, NULL)) return -1;

  return 0;
}

/**
 * @brief Attach a socket to a session, and shake hands with the peer.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  socket   Socket.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_attach (int socket, gnutls_session_t* session)
{
  struct sigaction new_action, original_action;

  gnutls_transport_set_ptr (*session,
                            (gnutls_transport_ptr_t) socket);

  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

  while (1)
    {
      int ret = gnutls_handshake (*session);
      if (ret >= 0)
        break;
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        continue;
      g_message ("Failed to shake hands with peer.");
      gnutls_perror (ret);
      if (shutdown (socket, SHUT_RDWR) == -1)
        g_message ("Failed to shutdown server socket");
      sigaction (SIGPIPE, &original_action, NULL);
      return -1;
    }
  g_message ("   Shook hands with peer.");

  if (sigaction (SIGPIPE, &original_action, NULL)) return -1;

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
  struct sigaction new_action, original_action;
  size_t left = strlen (string);

  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

  while (left)
    {
      ssize_t count;
      g_message ("   send %i from %.*s[...]", left, left < 30 ? left : 30, string);
      count = gnutls_record_send (*session, string, left);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              g_message ("   openvas_server_send rehandshake");
              continue;
            }
          g_message ("Failed to write to server.");
          gnutls_perror (count);
          sigaction (SIGPIPE, &original_action, NULL);
          return -1;
        }
      if (count == 0)
        {
          /* Server closed connection. */
          g_message ("=  server closed\n");
          sigaction (SIGPIPE, &original_action, NULL);
          return 1;
        }
      g_message ("=> %.*s", count, string);
      string += count;
      left -= count;
    }
  g_message ("=> done");

  sigaction (SIGPIPE, &original_action, NULL);
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
 * @param[in]   end_type            Connecton end type (GNUTLS_SERVER or
 *                                  GNUTLS_CLIENT).
 * @param[in]   ca_file             Certificate authority file.
 * @param[in]   cert_file           Certificate file.
 * @param[in]   key_file            Key file.
 * @param[out]  server_session      The session with the server.
 * @param[out]  server_credentials  Server credentials.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_new (gnutls_connection_end_t end_type,
                    gchar* ca_cert_file,
                    gchar* cert_file,
                    gchar* key_file,
                    gnutls_session_t* server_session,
                    gnutls_certificate_credentials_t* server_credentials)
{
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

  /* Turn off use of /dev/random, as this can block. */

  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  /* Initialize security library. */

  if (gnutls_global_init ())
    {
      g_message ("Failed to initialize GNUTLS.");
      return -1;
    }

  /* Setup server session. */

  if (gnutls_certificate_allocate_credentials (server_credentials))
    {
      g_warning ("%s: failed to allocate server credentials\n", __FUNCTION__);
      return -1;
    }

  if (cert_file
      && key_file
      && (gnutls_certificate_set_x509_key_file (*server_credentials,
                                                cert_file,
                                                key_file,
                                                GNUTLS_X509_FMT_PEM)
          < 0))
    {
      g_warning ("%s: failed to set credentials key file\n", __FUNCTION__);
      g_warning ("%s:   cert file: %s\n", __FUNCTION__, cert_file);
      g_warning ("%s:   key file : %s\n", __FUNCTION__, key_file);
      goto server_free_fail;
    }

  if (ca_cert_file
      && (gnutls_certificate_set_x509_trust_file (*server_credentials,
                                                  ca_cert_file,
                                                  GNUTLS_X509_FMT_PEM)
          < 0))
    {
      g_warning ("%s: failed to set credentials trust file: %s\n",
                 __FUNCTION__,
                 ca_cert_file);
      goto server_free_fail;
    }

  if (gnutls_init (server_session, end_type))
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

  gnutls_certificate_server_set_request (*server_session,
                                         GNUTLS_CERT_REQUEST);

  /* FIX */
  gnutls_session_enable_compatibility_mode (*server_session);

#if 0
  // FIX admin also had this

  gnutls_dh_set_prime_bits (session, DH_BITS);
#endif

  return 0;

 server_fail:
  (void) gnutls_deinit (*server_session);

 server_free_fail:
  gnutls_certificate_free_credentials (*server_credentials);

  return -1;
}

/** @todo vs openvas_server_close */
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
openvas_server_free (int server_socket,
                     gnutls_session_t server_session,
                     gnutls_certificate_credentials_t
                     server_credentials)
{
  struct sigaction new_action, original_action;

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

  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

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

  if (sigaction (SIGPIPE, &original_action, NULL)) return -1;

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

  gnutls_global_deinit ();

  return 0;
}
