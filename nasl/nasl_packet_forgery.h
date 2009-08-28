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
#ifndef NASL_PACKET_FORGERY_H


tree_cell* forge_ip_packet(lex_ctxt*);
tree_cell* set_ip_elements(lex_ctxt*);
tree_cell* get_ip_element(lex_ctxt*);
tree_cell* dump_ip_packet(lex_ctxt*);
tree_cell* insert_ip_options(lex_ctxt*);


tree_cell * forge_tcp_packet(lex_ctxt *);
tree_cell * get_tcp_element(lex_ctxt *);
tree_cell * set_tcp_elements(lex_ctxt *);
tree_cell * dump_tcp_packet(lex_ctxt *);


tree_cell * forge_udp_packet(lex_ctxt *);
tree_cell * set_udp_elements(lex_ctxt *);
tree_cell * dump_udp_packet(lex_ctxt *);
tree_cell * get_udp_element(lex_ctxt *);


tree_cell *  forge_icmp_packet(lex_ctxt *);
tree_cell *  get_icmp_element(lex_ctxt *);


tree_cell* forge_igmp_packet(lex_ctxt *);


tree_cell * nasl_tcp_ping(lex_ctxt *);

tree_cell * nasl_send_packet(lex_ctxt *);
tree_cell * nasl_pcap_next(lex_ctxt *);
tree_cell * nasl_send_capture(lex_ctxt *);
#endif
