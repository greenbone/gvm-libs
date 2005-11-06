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
 *
 * scanners_utils -- scanner-plugins-specific stuff
 */

#define EXPORTING
#include <includes.h>
#include "comm.h"
#include "services.h"
 
/*
 * Sends the status of an action
 */
ExtFunc
int 
comm_send_status(globals, hostname, action,curr,max)
  struct arglist * globals;
  char * hostname;
  char * action;
  int curr, max;
{
 struct arglist * prefs = arg_get_value(globals,"preferences");
 char * pref = arg_get_value(prefs, "ntp_short_status");
 int short_status;
 ntp_caps* caps = arg_get_value(globals, "ntp_caps");
 int soc = (int)arg_get_value(globals, "global_socket");
 char buffer[2048];
 int e, n = 0, l, ack;
 fd_set rd, wr;
 struct timeval tv;
 
 
 if (soc < 0 || soc > 1024) 
  return -1;
 
 
 if(strlen(hostname) > (sizeof(buffer) - 50))
  return -1;
  
 if(pref && !strcmp(pref, "yes"))
  short_status = 1;
 else
  short_status = 0;
   
  if(caps->ntp_11)
    {
    if(short_status)
      {
      snprintf(buffer, sizeof(buffer), "s:%c:%s:%d:%d\n", action[0], hostname, curr, max);
      }
    else
     snprintf(buffer, sizeof(buffer),
		"SERVER <|> STATUS <|> %s <|> %s <|> %d/%d <|> SERVER\n",
		hostname, action, curr, max);
    }
  else
   snprintf(buffer, sizeof(buffer), "SERVER <|> STAT <|> %s <|> %d/%d <|> SERVER\n",
	      hostname, curr, max);
	      
	      
 internal_send(soc, buffer, INTERNAL_COMM_MSG_TYPE_DATA);
 
 return 0;
}



/*
 * 0 is considered as the biggest number, since it
 * ends our string
 */
int qsort_compar(const void* a, const void* b)
{
 u_short *aa = (u_short*)a;
 u_short *bb = (u_short*)b;
 if(*aa==0)return(1);
 else if(*bb==0)return(-1);
 else return(*aa-*bb);
}


/*
 * getpts()
 * 
 * This function is (c) Fyodor <fyodor@dhp.com> and was taken from
 * his excellent and outstanding scanner Nmap
 * See http://www.insecure.org/nmap/ for details about 
 * Nmap
 */
 
/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array 
   of port numbers*/
unsigned short *getpts(char *origexpr, int * len) {
int exlen;
char *p,*q;
unsigned short *tmp, *ports;
int i=0, j=0,start,end;
char *expr;
char *mem;
char * s_start, * s_end;
static unsigned short * last_ret = NULL;
static char * last_expr = NULL;
static int last_num;

 if(strcmp(origexpr, "default") == 0)
	 {
	 if ( last_expr != NULL )
	   efree(&last_expr);
 	 if ( last_ret != NULL )
	  efree(&last_ret);
  	 last_expr = estrdup(origexpr);
  	 last_ret  = get_tcp_svcs(&last_num);
	 if ( len != NULL )
	 	*len = last_num;	
	 return last_ret;
	}

 expr = estrdup(origexpr);
 exlen = strlen(origexpr);
 mem = expr;

if( last_expr != NULL)
{
 if(strcmp(last_expr, expr) == 0)
  {
  if(len != NULL)*len = last_num;
  efree(&mem);
  return last_ret;
 }
 else
 { 
  efree(&last_expr);
  efree(&last_ret);
 }
}




ports = emalloc(65536 * sizeof(short));
for(;j < exlen; j++) 
  if (expr[j] != ' ') expr[i++] = expr[j]; 
expr[i] = '\0';

if((s_start = strstr(expr, "T:")) != NULL)
{
 expr = &(s_start[2]);
}

if((s_end = strstr(expr, "U:")) != NULL)
{
   if(s_end[-1] == ',')
     s_end --;
 s_end[0] = '\0';
}


exlen = i;
i=0;
while((p = strchr(expr,','))) {
  *p = '\0';
  if (*expr == '-') {start = 1; end = atoi(expr+ 1);}
  else {
    start = end = atoi(expr);
    if ((q = strchr(expr,'-')) && *(q+1) ) end = atoi(q + 1);
    else if (q && !*(q+1)) end = 65535;
  }
  if(start  < 1)start = 1;
  if(start > end){
	efree(&mem);
	return NULL;
	}
  for(j=start; j <= end; j++) 
    ports[i++] = j;
  expr = p + 1;
}
if (*expr == '-') {
  start = 1;
  end = atoi(expr+ 1);
}
else {
  start = end = atoi(expr);
  if ((q =  strchr(expr,'-')) && *(q+1) ) end = atoi(q+1);
  else if (q && !*(q+1)) end = 65535;
}
if(start < 1) start = 1;
if (start > end) {
	efree(&mem);
	return NULL;
	}
for(j=start; j <= end; j++) 
  ports[i++] = j;
ports[i++] = 0;
  
  


  qsort(ports, i, sizeof(u_short), qsort_compar);
  tmp = realloc(ports, i * sizeof(short));
  if(len != NULL)*len = i - 1;
  efree(&mem);
  
  last_ret = tmp;
  last_expr = estrdup(origexpr);
  last_num =  i - 1;
  return tmp;
}
