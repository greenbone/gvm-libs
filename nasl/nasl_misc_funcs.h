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
#ifndef NASL_MISC_FUNCS_H
#define NASL_MISC_FUNCS_H
tree_cell * nasl_rand(lex_ctxt * );
tree_cell * nasl_usleep(lex_ctxt * );
tree_cell * nasl_sleep(lex_ctxt * );
tree_cell * nasl_ftp_log_in(lex_ctxt * );
tree_cell * nasl_ftp_get_pasv_address(lex_ctxt * );
tree_cell * nasl_telnet_init(lex_ctxt * );
tree_cell * nasl_start_denial(lex_ctxt * );
tree_cell * nasl_end_denial(lex_ctxt * );
tree_cell* nasl_dump_ctxt(lex_ctxt* );
tree_cell* nasl_do_exit(lex_ctxt* );
tree_cell* nasl_isnull(lex_ctxt* );
tree_cell* nasl_make_list(lex_ctxt*);
tree_cell* nasl_make_array(lex_ctxt*);
tree_cell* nasl_keys(lex_ctxt*);
tree_cell* nasl_max_index(lex_ctxt*);
tree_cell* nasl_typeof(lex_ctxt*);
tree_cell* nasl_defined_func(lex_ctxt*);
tree_cell* nasl_func_named_args(lex_ctxt*);
tree_cell* nasl_func_unnamed_args(lex_ctxt*);
tree_cell* nasl_func_has_arg(lex_ctxt*);
tree_cell* nasl_sort_array(lex_ctxt*);
tree_cell* nasl_unixtime(lex_ctxt*);
tree_cell* nasl_gettimeofday(lex_ctxt*);
tree_cell* nasl_localtime(lex_ctxt*);
tree_cell* nasl_mktime(lex_ctxt*);
tree_cell* nasl_open_sock_kdc(lex_ctxt*);

#endif
