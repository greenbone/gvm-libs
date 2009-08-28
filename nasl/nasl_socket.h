/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison and Michel Arboi
 * give permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 */
 /* -------------------------------------------------------------------- *
  * This file contains all the functions related to the handling of the  *
  * sockets within a NASL script - namely, this is the implementation    *
  * of open_(priv_)?sock_(udp|tcp)(), send(), recv(), recv_line() and    *
  * close().								 *
  *----------------------------------------------------------------------*/
  
  
  
/*--------------------------------------------------------------------------*/
#ifndef NASL_SOCKET_H
#define NASL_SOCKET_H

tree_cell * nasl_open_sock_tcp(lex_ctxt *);
tree_cell * nasl_open_sock_udp(lex_ctxt *);
/* private func */
tree_cell * nasl_open_sock_tcp_bufsz(lex_ctxt *, int);
tree_cell * nasl_socket_get_error(lex_ctxt*);

tree_cell * nasl_open_priv_sock_tcp(lex_ctxt *);
tree_cell * nasl_open_priv_sock_udp(lex_ctxt *);

tree_cell * nasl_send(lex_ctxt *);

tree_cell * nasl_recv(lex_ctxt *);
tree_cell * nasl_recv_line(lex_ctxt *);

tree_cell * nasl_close_socket(lex_ctxt *);

tree_cell * nasl_join_multicast_group(lex_ctxt *);
tree_cell * nasl_leave_multicast_group(lex_ctxt *);

tree_cell * nasl_get_source_port(lex_ctxt*);

#endif
