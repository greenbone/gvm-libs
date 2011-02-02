/* OpenVAS Libraries
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


#ifndef _OPENVAS_SERVICES_H
#define _OPENVAS_SERVICES_H

#include "services1.h"

/* **** FILES **** */

#define OPENVAS_SERVICES	 OPENVAS_DATA_DIR "/openvas-services"
/* If you want OpenVAS to use a second input file, uncomment next line */
/*#define OPENVAS_IANA_PORTS	CONF_DIR "/iana-port-numbers"*/

#define OPENVAS_SERVICES_TCP	OPENVAS_STATE_DIR "/services.tcp"
#define OPENVAS_SERVICES_UDP	OPENVAS_STATE_DIR "/services.udp"
/* Not really useful but for debug or information */
#define OPENVAS_SERVICES_TXT	OPENVAS_STATE_DIR "/services.txt"

#define SERVICES_MAGIC 0x42

struct openvas_service
{
  char magic;
  unsigned short ns_port;
  char ns_name[128];
};

const char *openvas_get_svc_name (int, const char *);
unsigned short *get_tcp_svcs (int *);

#endif
