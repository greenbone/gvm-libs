/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   
 

#ifndef _NESSUSL_NETWORK_H
#define _NESSUSL_NETWORK_H

int recv_line(int, char  *, size_t);
int    open_stream_connection(struct arglist *, unsigned int, int, int);
int    open_stream_connection_unknown_encaps(struct arglist *, unsigned int, int, int *);
int    open_stream_connection_unknown_encaps5(struct arglist *, unsigned int, int, int *, int*);
int    open_stream_auto_encaps(struct arglist *, unsigned int, int);
int    write_stream_connection (int, void * buf, int n);
int    read_stream_connection (int, void * buf, int);
int    read_stream_connection_min(int, void*, int, int);
int    close_stream_connection(int);
int    nsend(int, void*, int, int);
const char* get_encaps_name(int);
const char* get_encaps_through(int);

int    stream_set_timeout(int, int);
int    stream_set_options(int, int, int);

int	fd_is_stream(int);

struct in_addr socket_get_next_source_addr();
int set_socket_source_addr(int, int);
void socket_source_init(struct in_addr *);


#ifdef HAVE_SSL
       X509*   stream_get_server_certificate(int);
ExtFunc	       char*   stream_get_ascii_server_certificate(int);
#endif
#endif
