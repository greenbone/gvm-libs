/**
 * GnuTLS based functions for communication with an OpenVAS server.
 * Copyright (C) 2009  Greenbone Networks GmbH
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
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
#include <fcntl.h>
#include <string.h>

#include "openvas_server.h"

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
openvas_server_connect_to_server (gnutls_session_t * session,
                                  char *host, int port)
{
  // TODO: Ensure that host and port have sane values.
  // TODO: Improve logging.

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

  if (!inet_aton(host, &address.sin_addr))
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
 * @brief Connect to the server.
 *
 * @param[in]  socket   Socket connected to server (from \ref connect_to_server).
 * @param[in]  session  GNUTLS session with server.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_close_server_connection (int socket, gnutls_session_t session)
{
  /* Turn off blocking. */
  if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1) return -1;

  gnutls_bye (session, GNUTLS_SHUT_RDWR);
  close (socket);
  return 0;
}

/**
 * @brief Send a string to the server.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  string   String to send.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_server_send_to_server (gnutls_session_t* session, const char* string)
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
openvas_server_sendf_to_server (gnutls_session_t* session, const char* format, ...)
{
  va_list args;
  va_start (args, format);
  gchar* msg = g_strdup_vprintf (format, args);
  int ret = openvas_server_send_to_server (session, msg);
  g_free (msg);
  va_end (args);
  return ret;
}


