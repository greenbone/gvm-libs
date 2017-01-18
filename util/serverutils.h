/* gvm-libs/util
 * $Id$
 * Description: GnuTLS based functions for server communication - headers.
 * Copyright (C) 2009  Greenbone Networks GmbH
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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
 * @file serverutils.h
 * @brief GnuTLS based functions for server communication - header file.
 *
 * This module supplies low-level communication functions for communication
 * with a server over GnuTLS.
 */

#ifndef _GVM_SERVERUTILS_H
#define _GVM_SERVERUTILS_H

#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif

#include <glib.h>
#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/param.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif
#include <netinet/ip.h>
#endif

/**
 * @brief Connection.
 */
typedef struct
{
  int tls;                      ///< Whether uses TCP-TLS (vs UNIX socket).
  int socket;                   ///< Socket.
  gnutls_session_t session;     ///< Session.
  gnutls_certificate_credentials_t credentials;  ///< Credentials.
  gchar *username;              ///< Username with which to connect.
  gchar *password;              ///< Password for user with which to connect.
  gchar *host_string;           ///< Server host string.
  gchar *port_string;           ///< Server port string.
  gint port;                    ///< Port of server.
  gboolean use_certs;           ///< Whether to use certs.
  gchar *ca_cert;               ///< CA certificate.
  gchar *pub_key;               ///< The public key.
  gchar *priv_key;              ///< The private key.
} gvm_connection_t;

void gvm_connection_free (gvm_connection_t *);

void gvm_connection_close (gvm_connection_t *);

int gvm_server_verify (gnutls_session_t);

int gvm_server_open (gnutls_session_t *, const char *, int);

int gvm_server_open_verify (gnutls_session_t *, const char *, int,
                            const char *, const char *, const char *, int);

int gvm_server_open_with_cert (gnutls_session_t *, const char *, int,
                               const char *, const char *, const char *);

int gvm_server_close (int, gnutls_session_t);

int gvm_server_connect (int, struct sockaddr_in *, gnutls_session_t *);

int gvm_server_attach (int, gnutls_session_t *);

int gvm_server_sendf (gnutls_session_t *, const char *, ...)
    __attribute__ ((format (printf, 2, 3)));

int gvm_server_vsendf (gnutls_session_t *, const char *, va_list);
int gvm_socket_vsendf (int, const char *, va_list);

int gvm_server_sendf_xml (gnutls_session_t *, const char *, ...);
int gvm_server_sendf_xml_quiet (gnutls_session_t *, const char *, ...);

int gvm_connection_sendf_xml (gvm_connection_t *, const char *, ...);
int gvm_connection_sendf_xml_quiet (gvm_connection_t *, const char *, ...);

int gvm_connection_sendf (gvm_connection_t *, const char *, ...);

int gvm_server_new (unsigned int, gchar *, gchar *, gchar *,
                    gnutls_session_t *, gnutls_certificate_credentials_t *);

int gvm_server_new_mem (unsigned int, const char *, const char *,
                        const char *, gnutls_session_t *,
                        gnutls_certificate_credentials_t *);

int gvm_server_free (int, gnutls_session_t,
                     gnutls_certificate_credentials_t);

int gvm_server_session_free (gnutls_session_t,
                             gnutls_certificate_credentials_t);

int
load_gnutls_file (const char *, gnutls_datum_t *);

void
unload_gnutls_file(gnutls_datum_t *);

int
set_gnutls_dhparams (gnutls_certificate_credentials_t, const char *);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* not _GVM_SERVERUTILS_H */
