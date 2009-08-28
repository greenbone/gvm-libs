/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
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
 */
 
 
 
 /* -------------------------------------------------------------------- *
  * This file contains all the functions related to the handling of the  *
  * sockets within a NASL script - namely, this is the implementation    *
  * of open_(priv_)?sock_(udp|tcp)(), send(), recv(), recv_line() and    *
  * close().								 *
  *----------------------------------------------------------------------*/
  
  
  
/*--------------------------------------------------------------------------*/
#include <includes.h>
#include "nasl.h"
#include "harglists.h"

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "strutils.h"

#include "nasl_packet_forgery.h"
#include "nasl_debug.h"

#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL EADDRINUSE
#endif
/*----------------------- Private functions ---------------------------*/

static int unblock_socket(int soc)
{
  int   flags =  fcntl(soc, F_GETFL, 0);
  if (flags < 0)
    {
      perror("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl(soc, F_SETFL, O_NONBLOCK | flags) < 0)
    {
      perror("fcntl(F_SETFL,O_NONBLOCK)");
      return -1;
    }
  return 0;
}

static int block_socket(int soc)
{
  int   flags =  fcntl(soc, F_GETFL, 0);
  if (flags < 0)
    {
      perror("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl(soc, F_SETFL, (~O_NONBLOCK) & flags) < 0)
    {
      perror("fcntl(F_SETFL,~O_NONBLOCK)");
      return -1;
    }
  return 0;
}


/*
 * NASL automatically re-send data when a recv() on a UDP packet
 * fails. The point is to take care of packets lost en route.
 *
 * To do this, we store a copy of the data sent by a given socket
 * each time send() is called, and we re-send() it each time 
 * recv() is called and fails
 *
 */
 
/* add udp data in our cache */
static int add_udp_data(struct arglist * script_infos, int soc, char * data, int len)
{
 harglst * udp_data = arg_get_value(script_infos, "udp_data");
 char name[12];
 if(udp_data == NULL)
 {
  udp_data = harg_create(123);
  arg_add_value(script_infos, "udp_data", ARG_PTR, -1, udp_data);
 }
 snprintf(name, sizeof(name), "%d", soc); /* RATS: ignore */
 
 if(harg_get_blob(udp_data, name) != NULL)
  harg_set_blob(udp_data, name, len, data);
 else
  harg_add_blob( udp_data, name, len, data);
 return 0;
}

/* get the udp data for socket <soc> */
static char * get_udp_data(struct arglist * script_infos, int soc, int * len)
{
 harglst * udp_data = arg_get_value(script_infos, "udp_data");
 char name[12];
 char * ret;
 
 if(udp_data == NULL)
  return NULL;
 
 snprintf(name, sizeof(name), "%d", soc); /* RATS: ignore */
 ret = harg_get_blob(udp_data, name);
 if(ret == NULL)
  return NULL;
 
 *len = harg_get_size(udp_data, name);
 return ret;
}

/* remove the udp data for socket <soc> */
static void rm_udp_data(struct arglist * script_infos, int soc)
{
 harglst * udp_data = arg_get_value(script_infos, "udp_data");
 char name[12];
 
 if(udp_data == NULL)
  return;
 
 snprintf(name, sizeof(name), "%d", soc); /* RATS: ignore */
 harg_remove(udp_data, name);
}


/*-------------------------------------------------------------------*/




static tree_cell * nasl_open_privileged_socket(lex_ctxt * lexic, int proto)
{
 struct arglist * script_infos = lexic->script_infos;
 int sport, current_sport = -1;
 int dport;
 int sock;
 int e;
 struct sockaddr_in addr, daddr;
 struct sockaddr_in6 addr6, daddr6;
 struct in6_addr * p;
 int to = get_int_local_var_by_name(lexic, "timeout", lexic->recv_timeout);
 tree_cell * retc;
 struct timeval tv;
 fd_set rd;
 int opt;
 unsigned int opt_sz;
 int family;
 
 
 
 sport = get_int_local_var_by_name(lexic, "sport", -1);
 dport = get_int_local_var_by_name(lexic, "dport", -1);
 if(dport <= 0)
   {
     nasl_perror(lexic, "open_private_socket: missing or undefined parameter dport!\n");
     return NULL;
   }
 
 if(sport < 0) current_sport = 1023;


restart: 
 p = plug_get_host_ip(script_infos);
 if(IN6_IS_ADDR_V4MAPPED(p))
 {
   family = AF_INET;
   bzero(&addr, sizeof(addr));
   if(proto == IPPROTO_TCP)
     sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   else
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
 }
 else
 {
   family = AF_INET6;
   bzero(&addr6, sizeof(addr6));
   if(proto == IPPROTO_TCP)
     sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
   else
     sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
 }
  
  
 /*
  * We will bind to a privileged port. Let's declare
  * our socket ready for reuse
  */
 
 if(sock < 0)
	 return NULL;

tryagain :
 if ( current_sport < 128 && sport < 0 ) return NULL;
 e =  set_socket_source_addr(sock, sport > 0 ? sport : current_sport--, family);
 
 /*
  * bind() failed - try again on a lower port
  */
 if(e < 0)
 {
  close ( sock );
  if(sport > 0) 
    return NULL;
   else 
     goto tryagain;
 }
 

 
 /*
  * Connect to the other end
  */
 p = plug_get_host_ip(script_infos);

 if(IN6_IS_ADDR_V4MAPPED(p))
 {
   bzero(&daddr, sizeof(daddr));
   daddr.sin_addr.s_addr = p->s6_addr32[3];
   daddr.sin_family = AF_INET;
   daddr.sin_port = htons(dport);
   unblock_socket(sock);
   e = connect(sock, (struct sockaddr*)&daddr, sizeof(daddr));
 }
 else
 {
   bzero(&daddr6, sizeof(daddr6));
   memcpy(&daddr6.sin6_addr,p, sizeof(daddr6));
   daddr6.sin6_family = AF_INET6;
   daddr6.sin6_port = htons(dport);
   unblock_socket(sock);
   e = connect(sock, (struct sockaddr*)&daddr6, sizeof(daddr6));
 }


 if ( e < 0 )
 {
   if ( errno == EADDRINUSE || errno == EADDRNOTAVAIL )
   {
     close(sock);
     if ( sport < 0 ) 
          goto restart;
     else  
          return NULL;
   }
   else if ( errno != EINPROGRESS )
   { 
     close(sock);
     return NULL;
   }
 }

  do {
  tv.tv_sec = to;
  tv.tv_usec = 0;
  FD_ZERO(&rd);
  FD_SET(sock, &rd);
  e = select(sock + 1, NULL, &rd, NULL, to > 0 ? &tv:NULL);
  } while ( e < 0 && errno == EINTR );

 if ( e <= 0 ) 
 {
   close ( sock );
   return FAKE_CELL;
 }

 block_socket(sock);
 opt_sz = sizeof(opt);

 if ( getsockopt(sock, SOL_SOCKET, SO_ERROR, &opt, &opt_sz) < 0 )
 {
  fprintf(stderr, "[%d] open_priv_sock()->getsockopt() failed : %s\n", getpid(), strerror(errno));
  close(sock);
  return NULL;
 }
 

 switch ( opt )
 {
   case EADDRINUSE:
   case EADDRNOTAVAIL:
     close ( sock );
     if ( sport < 0 )
 	 goto restart;
      else 
         return FAKE_CELL;

   case 0:
	break;
   default:
       close ( sock );
       return FAKE_CELL;
       break;
 }
 
 if(proto == IPPROTO_TCP)
   sock = nessus_register_connection(sock, NULL);

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = sock < 0 ? 0 : sock;
  return retc;
}


tree_cell * nasl_open_priv_sock_tcp(lex_ctxt * lexic)
{
 return nasl_open_privileged_socket(lexic, IPPROTO_TCP);
}

tree_cell * nasl_open_priv_sock_udp(lex_ctxt * lexic)
{
 return nasl_open_privileged_socket(lexic, IPPROTO_UDP);
}
 

/*--------------------------------------------------------------------------*/

tree_cell * nasl_open_sock_tcp_bufsz(lex_ctxt * lexic, int bufsz)
{
 int soc = -1;
 struct arglist *  script_infos = lexic->script_infos;
 int	to, port, transport = -1;
 tree_cell * retc;

 to = get_int_local_var_by_name(lexic, "timeout", lexic->recv_timeout*2);
 if(to < 0)
 	to = 10;
	
 transport = get_int_local_var_by_name(lexic, "transport", -1);
 if (bufsz < 0)
   bufsz = get_int_local_var_by_name(lexic, "bufsz", 0);
  
 port = get_int_var_by_num(lexic, 0, -1);
 if(port < 0)
	 return NULL;
 
 if(transport < 0)
   soc =  open_stream_auto_encaps(script_infos, port, to);
 else
   soc  = open_stream_connection(script_infos, port, transport, to);
 if (bufsz > 0 && soc >= 0 )
 {
   if (stream_set_buffer(soc, bufsz) < 0)
     nasl_perror(lexic, "stream_set_buffer: soc=%d,bufsz=%d\n", soc, bufsz);
 }

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = soc < 0 ? 0 : soc;

  return retc;
}

tree_cell * nasl_open_sock_tcp(lex_ctxt * lexic)
{
  return nasl_open_sock_tcp_bufsz(lexic, -1);
}

/*
 * Opening a UDP socket is a little more tricky, since
 * UDP works in a way which is different from TCP...
 * 
 * Our goal is to hide this difference for the end-user
 */
tree_cell * nasl_open_sock_udp(lex_ctxt * lexic)
{
 int soc;
 tree_cell * retc;
 int port;
 struct sockaddr_in soca;
 struct sockaddr_in6 soca6;
 struct arglist *  script_infos = lexic->script_infos;
 struct in6_addr * ia;

 port = get_int_var_by_num(lexic, 0, -1);
 if(port < 0)
	 return NULL;
   
 ia = plug_get_host_ip(script_infos);
 if ( ia == NULL ) return NULL;
 if(IN6_IS_ADDR_V4MAPPED(ia))
 {
   bzero(&soca, sizeof(soca));
   soca.sin_addr.s_addr = ia->s6_addr32[3];
   soca.sin_port = htons(port);
   soca.sin_family = AF_INET;

   soc = socket(AF_INET, SOCK_DGRAM, 0);
   set_socket_source_addr(soc, 0, AF_INET);
   connect(soc, (struct sockaddr*)&soca, sizeof(soca));
 }
 else
 {
   bzero(&soca6, sizeof(soca6));
   memcpy(&soca6.sin6_addr, ia, sizeof(struct in6_addr));
   soca6.sin6_port = htons(port);
   soca6.sin6_family = AF_INET6;

   soc = socket(AF_INET6, SOCK_DGRAM, 0);
   set_socket_source_addr(soc, 0, AF_INET6);
   connect(soc, (struct sockaddr*)&soca6, sizeof(soca6));
 }
 
 

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_INT;
 retc->x.i_val = soc < 0 ? 0 : soc;
 return retc;
}

/*---------------------------------------------------------------------*/

tree_cell * nasl_recv(lex_ctxt * lexic)
{
 char * data;
 int len = get_int_local_var_by_name(lexic, "length", -1);
 int min_len = get_int_local_var_by_name(lexic, "min", -1);
 int soc = get_int_local_var_by_name(lexic, "socket", 0);
 int to  = get_int_local_var_by_name(lexic, "timeout", lexic->recv_timeout);
 fd_set rd;
 struct timeval tv;
 int new_len = 0;
 tree_cell * retc;
 int type = -1;
 unsigned int opt_len = sizeof(type);
 int e;
 

 if(len <= 0 || soc <= 0)
	 return NULL;


 tv.tv_sec = to;
 tv.tv_usec = 0; 


 data = emalloc(len);
 if ( !fd_is_stream(soc) )
 	e = getsockopt(soc, SOL_SOCKET, SO_TYPE, &type, &opt_len);
  else
	e = -1;
 
 if(e == 0 && type == SOCK_DGRAM)
 {
 /*
  * As UDP packets may be lost, we retry up to 5 times
  */
 int retries = 5;
 int i;
 
 tv.tv_sec = to / retries;
 tv.tv_usec = (to % retries) *  100000;
 
 for(i=0;i<retries;i++)
 {
  FD_ZERO(&rd);
  FD_SET(soc, &rd);

  
  if(select(soc+1, &rd, NULL, NULL, &tv)>0)
  {
   int e;
   e = recv(soc, data+new_len, len-new_len, 0);
  
   if(e <= 0)
   {
    if(!new_len)
    {
     efree(&data); 
     return NULL;
    }
    else break;
   }
   else new_len+=e;
   if(new_len >= len)break;
   break; /* UDP data is never fragmented */
  }
  else 
  {
   /* 
    * The packet may have been lost en route - we resend it
    */
   char * data;
   int len;
   
   data = get_udp_data(lexic->script_infos, soc, &len);
   if(data != NULL)send(soc, data, len, 0);
   tv.tv_sec = to / retries;
   tv.tv_usec = ( to % retries) * 100000;
   }
  }
 }
 else {	
 	int old = stream_set_timeout(soc, tv.tv_sec);
 	new_len = read_stream_connection_min(soc, data, min_len, len);
	stream_set_timeout(soc, old);
      }
 if(new_len > 0)
 {
  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->x.str_val = nasl_strndup(data, new_len);
  retc->size = new_len;
  efree(&data);
  return retc;
 }
 else {
	 efree(&data);
	 return NULL;
  }
}



tree_cell * nasl_recv_line(lex_ctxt * lexic)
{
 int len = get_int_local_var_by_name(lexic, "length", -1);
 int soc = get_int_local_var_by_name(lexic, "socket", 0);
 int timeout = get_int_local_var_by_name(lexic, "timeout", -1);
 char * data;
 int new_len = 0;
 int n = 0;
 tree_cell * retc;
 time_t		t1 = 0;

 if(len == -1 || soc <= 0)
   {
     nasl_perror(lexic, "recv_line: missing or undefined parameter length or soc\n");
     return NULL;
   }

 if (timeout >= 0)	/* sycalls are much more expensive than simple tests */
   t1 = time(NULL);

 if ( fd_is_stream(soc) != 0 )
 {
  int bufsz = stream_get_buffer_sz ( soc );
  if ( bufsz <= 0 )
	stream_set_buffer(soc, len + 1 );
 }

 data = emalloc(len+1);
 for(;;)
 {
  int e = read_stream_connection_min(soc, data+n, 1, 1);
  if(e < 0)
    break;
  if(e == 0)
  {
   if( timeout >= 0 && time(NULL) - t1 < timeout)
  	continue;
    else 
  	break;
  }	
  n++;  
  if((data[n-1] == '\n') ||
     (n >= len))break;
 }
 
 
 
 if(n <= 0)
   {
     efree(&data);
     return NULL;
   }
 
 new_len = n;
 
 
  

 retc = alloc_tree_cell(0, NULL);
 retc->type = CONST_DATA;
 retc->size = new_len;
 retc->x.str_val = nasl_strndup(data, new_len);

 efree(&data);

 return retc;
}

/*---------------------------------------------------------------------*/

tree_cell * nasl_send(lex_ctxt * lexic)
{
 int soc = get_int_local_var_by_name(lexic, "socket", 0);
 char * data = get_str_local_var_by_name(lexic, "data");
 int option = get_int_local_var_by_name(lexic, "option", 0);
 int length = get_int_local_var_by_name(lexic, "length", 0);
 int data_length = get_var_size_by_name(lexic, "data");
 int n;
 tree_cell * retc;
 int type;
 unsigned int type_len = sizeof(type);

 
 if(soc <= 0 || data == NULL)
 {
 	nasl_perror(lexic, "Syntax error with the send() function\n");
	nasl_perror(lexic, "Correct syntax is : send(socket:<soc>, data:<data>\n");
	return NULL;
 }

 if( length <= 0 || length > data_length )
	length = data_length;
 
 
 if(!fd_is_stream(soc) && 
    getsockopt(soc, SOL_SOCKET, SO_TYPE, &type, &type_len) == 0 &&
    type == SOCK_DGRAM)
 {
		n = send(soc, data, length, option);
		add_udp_data(lexic->script_infos, soc, data, length);
 }
 else
  n = nsend(soc, data, length,option);
			

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = n;

  return retc;
}



/*---------------------------------------------------------------------*/
tree_cell * nasl_close_socket(lex_ctxt * lexic)
{
 int soc;
 int type;
 unsigned int opt_len = sizeof(type);
 int e;
 
 soc = get_int_var_by_num(lexic, 0, -1);
 /* XXX: These are thoughts expressed on the openvas-devel mailing list 2008-08-06:
  *
  * nasl_close_socket seems to be the only place in nasl/nasl_socket.c where the
  * value of the socket filedescriptor is checked in this way.  That in itself is
  * strange.  Why only there?  Also, why can't the socket fd be less than 4?  I
  * could sort of understand 3 (0, 1, 2 are already taken by the standard
  * streams) but 4? Does the openvas server and/or the NASL interpreter guarantee
  * that at least one other file is open?
  *
  * My guess is that the check is there to prevent NASL scripts from closing file
  * descriptors needed by openvas/NASL which includes the ones it uses for
  * accessing the knowledgebase.  If that's the case, then the test has too much
  * knowledge of the circumstances under which the NASL interpreter runs.  It
  * should be moved to a separate function whose behavior can be influenced by
  * the program embedding the NASL interpreter.  Other functions should probably
  * also check the descriptors.
  *
  * I also wonder whether the original code (disallowing any file descriptor <= 4) 
  * actually was correct and the real defect is that open_sock_udp actually
  * returned 4.  Under which circumstances does it actually do that?  In my brief
  * tests with the stand-alone nasl interpreter the smallest number it returned
  * was 5.
 */
 if(soc < 4)
	{
 	 nasl_perror(lexic, "close(): invalid argument\n");
	 return NULL;
 	}

 if ( fd_is_stream(soc) )
  return close_stream_connection(soc) < 0 ? NULL:FAKE_CELL;
 
 e = getsockopt(soc, SOL_SOCKET, SO_TYPE, &type, &opt_len);
 if(e == 0 )
 {
  if (type == SOCK_DGRAM)
  {
   rm_udp_data(lexic->script_infos, soc);
   return FAKE_CELL;
  }
  close(soc);
  return FAKE_CELL;
 }
 else nasl_perror(lexic, "close(): invalid argument\n");

 return NULL;
}


static struct jmg {
  struct in_addr	in;
  int			count;
  int			s;
} *jmg_desc = NULL;
static int	jmg_max = 0;

tree_cell*
nasl_join_multicast_group(lex_ctxt *lexic)
{
  char		*a;
  int		s, i, j;
  struct ip_mreq	m;
  tree_cell	*retc = NULL;
  void		*p;


  a = get_str_var_by_num(lexic, 0);
  if (a == NULL)
    {
      nasl_perror(lexic, "join_multicast_group: missing parameter\n");
      return NULL;
    }
  if (! inet_aton(a, &m.imr_multiaddr))
    {
      nasl_perror(lexic, "join_multicast_group: invalid parameter '%s'\n", a);
      return NULL;
    }
  m.imr_interface.s_addr = INADDR_ANY;

  j = -1;
  for (i = 0; i < jmg_max; i ++)
    if (jmg_desc[i].in.s_addr == m.imr_multiaddr.s_addr && jmg_desc[i].count > 0)
      {
	jmg_desc[i].count ++;
	break;
      }
    else if (jmg_desc[i].count <= 0)
      j = i;
      

  if (i >= jmg_max)
    {
      s = socket(AF_INET, SOCK_DGRAM, 0);
      if (s < 0)
	{
	  nasl_perror(lexic, "join_multicast_group: socket: %s\n", strerror(errno));
	  return NULL;
	}
  
      if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m)) < 0)
	{
	  nasl_perror(lexic, "join_multicast_group: setsockopt(IP_ADD_MEMBERSHIP): %s\n", strerror(errno));
	  close(s);
	  return NULL;
	}

      if (j < 0)
	{
	  p = erealloc(jmg_desc, sizeof(*jmg_desc) * (jmg_max + 1));
	  if (p == NULL)
	    {
	      nasl_perror(lexic, "join_multicast_group: realloc failed\n");
	      close(s);
	      return NULL;
	    }
	  jmg_desc = p;
	  j = jmg_max ++;
	}
      jmg_desc[j].s = s;
      jmg_desc[j].in = m.imr_multiaddr;
      jmg_desc[j].count = 1;
    }

  retc = alloc_typed_cell(CONST_INT);
  retc->x.i_val = 1;
  return retc;
}


tree_cell*
nasl_leave_multicast_group(lex_ctxt *lexic)
{
  char		*a;
  struct in_addr	ia;
  int		i;

  a = get_str_var_by_num(lexic, 0);
  if (a == NULL)
    {
      nasl_perror(lexic, "leave_multicast_group: missing parameter\n");
      return NULL;
    }
  if (! inet_aton(a, &ia))
    {
      nasl_perror(lexic, "leave_multicast_group: invalid parameter '%s'\n", a);
      return NULL;
    }

  for (i = 0; i < jmg_max; i ++)
    if (jmg_desc[i].count > 0 && jmg_desc[i].in.s_addr == ia.s_addr)
      {
	if (-- jmg_desc[i].count <= 0)
	  close(jmg_desc[i].s);
	return FAKE_CELL;
      }

  nasl_perror(lexic, "leave_multicast_group: never joined group %s\n", a);
  return NULL;
}

tree_cell*
nasl_get_source_port(lex_ctxt* lexic)
{
  struct sockaddr_in	ia;
  int		s, fd;
  unsigned  int	l;
  tree_cell	*retc;
  int         type;
  unsigned int type_len = sizeof(type);

  s = get_int_var_by_num(lexic, 0, -1);
  if (s < 0)
    {
      nasl_perror(lexic, "get_source_port: missing socket parameter\n");
      return NULL;
    }
  if(!fd_is_stream(s) && getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &type_len) == 0 && type == SOCK_DGRAM)
       fd = s;
   else
       fd = nessus_get_socket_from_connection(s);
 

  if (fd < 0)
    {
      nasl_perror(lexic, "get_source_port: invalid socket parameter %d\n", s);
      return NULL;
    }
  l = sizeof(ia);
  if (getsockname(fd, (struct sockaddr*)&ia, &l) < 0)
    {
      nasl_perror(lexic, "get_source_port: getsockname(%d): %s\n", fd, strerror(errno));
      return NULL;
    }
  retc = alloc_typed_cell(CONST_INT);
  retc->x.i_val = ntohs(ia.sin_port);
  return retc;  
}



tree_cell*
nasl_socket_get_error(lex_ctxt* lexic)
{
  int soc = get_int_var_by_num(lexic, 0, -1);
  tree_cell * retc;
  int err;

  if ( soc < 0 || ! fd_is_stream(soc) )
	return NULL;

  err = stream_get_err(soc);
  retc = alloc_typed_cell(CONST_INT);
  
  switch ( err )
  {
    case 0 :
	retc->x.i_val = NASL_ERR_NOERR;
	break;
    case ETIMEDOUT:
	retc->x.i_val = NASL_ERR_ETIMEDOUT;
	break;
    case EBADF:
    case EPIPE:
#ifdef ECONNRESET
    case ECONNRESET:
#endif
#ifdef ENOTSOCK
    case ENOTSOCK:
#endif
	 retc->x.i_val = NASL_ERR_ECONNRESET;
         break;

    case ENETUNREACH:
    case EHOSTUNREACH:
	 retc->x.i_val = NASL_ERR_EUNREACH;
         break;

default:
	fprintf(stderr, "Unknown error %d %s\n", err, strerror(err));
  }


 return retc;
}
