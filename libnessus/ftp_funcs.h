/* OpenVAS
* $Id$
* Description: Header for ftp_funcs.c.
*
* Authors: - Renaud Deraison <mailto:deraison@nessus.org> (Original pre-fork development)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
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
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/


#ifndef FTP_FUNCS_H__
#define FTP_FUNCS_H__
ExtFunc int ftp_log_in(int , char * , char * );
ExtFunc int ftp_get_pasv_address(int , struct sockaddr_in * );
#endif
