/**
 * GnuTLS based functions for communication with an OpenVAS server - header.
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
 * @file openvas_server.h
 * @brief GnuTLS based functions for communication with an OpenVAS server -
 * header file.
 *
 * This library supplies low-level communication functions for communication
 * with an OpenVAS server over GnuTLS.
 */

#ifndef _OPENVAS_LIBRARIES_SERVER_H
#define _OPENVAS_LIBRARIES_SERVER_H

#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/ip.h>
#endif

int openvas_server_verify (gnutls_session_t);

int openvas_server_open (gnutls_session_t *, const char *, int);

int
openvas_server_open_with_cert (gnutls_session_t *, const char *, int,
                               const char *, const char *, const char *);

int openvas_server_close (int, gnutls_session_t);

int openvas_server_connect (int, struct sockaddr_in *, gnutls_session_t *,
                            gboolean);

int openvas_server_attach (int, gnutls_session_t *);

int openvas_server_send (gnutls_session_t *, const char *);

int openvas_server_sendf (gnutls_session_t *, const char *, ...);

int openvas_server_sendf_xml (gnutls_session_t *, const char *, ...);

int openvas_server_new (unsigned int, gchar *, gchar *, gchar *,
                        gnutls_session_t *, gnutls_certificate_credentials_t *);

int openvas_server_free (int, gnutls_session_t,
                         gnutls_certificate_credentials_t);

int openvas_server_session_free (gnutls_session_t,
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

#endif /* not _OPENVAS_LIBRARIES_SERVER_H */
