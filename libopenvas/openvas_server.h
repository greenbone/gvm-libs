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

#include <gnutls/gnutls.h>

int
openvas_server_connect_to_server (gnutls_session_t *, char*, int);

int
openvas_server_close_server_connection (int, gnutls_session_t);

int
openvas_server_send_to_server (gnutls_session_t*, const char*);

int
openvas_server_sendf_to_server (gnutls_session_t*, const char*, ...);
