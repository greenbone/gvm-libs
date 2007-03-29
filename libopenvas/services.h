/* 
 * Copyright (C) 2002 Michel Arboi
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
 

#ifndef _NESSUSL_SERVICES_H
#define _NESSUSL_SERVICES_H

/* **** Config **** */
/* If you want Nessus to switch to the system services file when its own file 
 * fails, UNdefine the next symbol. Otherwise, /etc/services is read only 
 * once when nessus-services is rebuilt */
#define NESSUS_SVC_READS_ETC_SERVICES

/* If you want Nessus to sort the services file before reading them,
 * define the next symbol.
 * Note : using popen() might be dangerous! Check that $PATH does not
 * contain any special character */
/*#define NESSUS_SVC_SORT_FILES*/

/* **** FILES **** */

#define NESSUS_SERVICES		NESSUS_STATE_DIR "/nessus/nessus-services"
/* If you want Nessus to use a second input file, uncomment next line */
/*#define NESSUS_IANA_PORTS	CONF_DIR "/iana-port-numbers"*/

#define NESSUS_SERVICES_TCP	NESSUS_STATE_DIR	"/nessus/services.tcp"
#define NESSUS_SERVICES_UDP	NESSUS_STATE_DIR	"/nessus/services.udp"
/* Not really useful but for debug or information */
#define NESSUS_SERVICES_TXT	NESSUS_STATE_DIR	"/nessus/services.txt"

#define SERVICES_MAGIC 0x42

struct nessus_service {
  char		 	magic;
  unsigned short	ns_port;
  char			ns_name[128];
};

ExtFunc const char*	nessus_get_svc_name(int, const char*);
ExtFunc int		nessus_init_svc(void);
ExtFunc unsigned short * get_tcp_svcs(int * );

#endif
