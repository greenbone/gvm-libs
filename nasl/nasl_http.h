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
#ifndef NASL_HTTP_H
#define NASL_HTTP_H

tree_cell * http_open_socket(lex_ctxt *);
tree_cell * http_close_socket(lex_ctxt *);
tree_cell * http_get(lex_ctxt *);
tree_cell * http_head(lex_ctxt *);
tree_cell * http_post(lex_ctxt *);
tree_cell * http_delete(lex_ctxt *);
tree_cell * http_put(lex_ctxt *);
tree_cell * nasl_http_recv_headers(lex_ctxt *);
tree_cell * cgibin(lex_ctxt *);
tree_cell * nasl_is_cgi_installed(lex_ctxt *);

tree_cell * nasl_http_keepalive_send_recv(lex_ctxt * );
tree_cell * nasl_http_share_exists(lex_ctxt *);
#endif
