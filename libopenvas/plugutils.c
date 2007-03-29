/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 - 2003 Renaud Deraison
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
 * Plugutils -- plugin-specific stuff
 */

#define EXPORTING
#include <includes.h>
#include "comm.h"
#include "harglists.h"
#include "diff.h"
#include "rand.h"
#include "services.h"
#include "store.h"

/* want version stuff */
#include "libvers.h"
#include "scanners_utils.h"


#undef DEBUG_DIFF_SCAN



char *nessuslib_version()
{
  static char vers[255];
  strncpy(vers, VERSION, sizeof(vers) - 1);
  vers[sizeof(vers) - 1 ] = '\0';
  return vers;
}
ExtFunc
void nessus_lib_version(major, minor, rev)
 int * major, *minor, *rev;
{
 *major = NL_MAJOR;
 *minor = NL_MINOR;
 *rev   = NL_REV;
}

#ifdef USE_PTHREADS
ExtFunc 
int nessuslib_pthreads_enabled()
{
 int enabled = 1;
 return(enabled);
}
#endif





/*
 * Escapes \n and \r properly. The resulting string
 * is copied in another buffer.
 */
ExtFunc char * 
addslashes(in)
	char * in;
{
 char * ret;
 char * out = malloc(strlen(in) * 2 + 1);
 bzero(out, strlen(in) * 2 + 1);
 ret = out;
 while(in[0])
 {
  if(in[0] == '\\')
  {
   out[0] = '\\'; out++;
   out[0] = '\\'; out++;
  }

  else if(in[0] == '\n')
  {
   out[0] = '\\'; out++;
   out[0] = 'n'; out++;
  }
  else if(in[0] == '\r')
  {
    out[0] = '\\'; out++;
    out[0] = 'r';  out++;
  }
  else {
	  out[0] = in[0];
	  out++;
  }
  in++;
 }
 return realloc(ret, strlen(ret) + 1);
}

/*
 * Replaces escape codes (\n, \r) by the real value
 * The resulting string is stored in another buffer
 */
ExtFunc char * 
rmslashes(in)
 char * in;
{
 char * out = malloc(strlen(in) + 1);
 char * ret = out;
 bzero(out, strlen(in) + 1);
 while(in[0])
 {
  if(in[0] == '\\')
  {
   switch(in[1])
   {
    case 'r' :
      out[0] = '\r';
      in++;
      break;
    case 'n' :
      out[0] =  '\n';
      in++;
      break;
    case '\\' :
      out[0] = '\\';
      in++;
      break;
    default :
      fprintf(stderr, "Unknown escape sequence '\\%c'\n", in[1]);
   }
  }
  else out[0] = in[0];
  in++;
  out++;
 }
 return realloc(ret, strlen(ret) + 1);
}


ExtFunc
void plug_set_version(desc, version)
 struct arglist * desc;
 const char* version;
{
 arg_add_value(desc, "VERSION", ARG_STRING, strlen(version), estrdup((char*)version));
}


ExtFunc 
char * _plug_get_version(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "VERSION");
}


ExtFunc 
char * plug_get_version(struct arglist * desc)
{
 return store_fetch_version(desc);
}


ExtFunc
void plug_set_path(desc, path)
 struct arglist * desc;
 const char * path;
{
 arg_add_value(desc, "PATH", ARG_STRING, strlen(path), estrdup((char*)path));
}

ExtFunc 
char * _plug_get_path(struct arglist * desc)
{
 return arg_get_value(desc, "PATH");
}

ExtFunc 
char * plug_get_path(desc)
 struct arglist * desc;
{
 return _plug_get_path(desc);
}



ExtFunc
void plug_set_fname(desc, filename)
 struct arglist * desc;
 const char * filename;
{
 arg_add_value(desc, "FILENAME", ARG_STRING, strlen(filename), estrdup(filename));
}

ExtFunc 
char * _plug_get_fname(struct arglist * desc)
{
 return arg_get_value(desc, "FILENAME");
}

ExtFunc 
char * plug_get_fname(desc)
 struct arglist * desc;
{
 return _plug_get_fname(desc);
}


ExtFunc
void plug_set_id(desc, id)
 struct arglist * desc;
 int id;
{
 arg_add_value(desc, "ID", ARG_INT, sizeof(int), (void*)id);
}

ExtFunc int
_plug_get_id(desc)
 struct arglist * desc;
{
 return (int)arg_get_value(desc, "ID");
}

ExtFunc int
plug_get_id(struct arglist * desc)
{
 return _plug_get_id(desc);	/* Never cached */
}


ExtFunc
void plug_set_cve_id(desc, id)
 struct arglist * desc;
 char * id;
{
 char * old = arg_get_value(desc, "CVE_ID");
 if(old != NULL)
 {
  old = erealloc(old, strlen(old) + strlen(id) + 3);
  strcat(old, ", ");
  strcat(old, id);
  arg_set_value(desc, "CVE_ID", strlen(old), old);
 }
 else
  arg_add_value(desc, "CVE_ID", ARG_STRING, strlen(id), estrdup(id));
}


ExtFunc char *
_plug_get_cve_id(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "CVE_ID");
}

ExtFunc char * plug_get_cve_id(struct arglist * desc)
{
 return store_fetch_cve_id(desc);
}


ExtFunc
void plug_set_bugtraq_id(desc, id)
 struct arglist * desc;
 char * id;
{
 char * old = arg_get_value(desc, "BUGTRAQ_ID");
 if(old != NULL)
 { 
  old = erealloc(old, strlen(old) + strlen(id) + 3);
  strcat(old, ", ");
  strcat(old, id);
  arg_set_value(desc, "BUGTRAQ_ID", strlen(old), old);
 }
 else
  arg_add_value(desc, "BUGTRAQ_ID", ARG_STRING, strlen(id), estrdup(id));
}

ExtFunc char * _plug_get_bugtraq_id(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "BUGTRAQ_ID");
}

ExtFunc char * plug_get_bugtraq_id(struct arglist * desc)
{
 return store_fetch_bugtraq_id(desc);
}



ExtFunc
void plug_set_xref(desc,name, value)
 struct arglist * desc;
 char * name, * value;
{
 char * old = arg_get_value(desc, "XREFS");
 if(old != NULL)
 { 
  old = erealloc(old, strlen(old) + strlen(name) + strlen(value) + 4);
  strcat(old, ", ");
  strcat(old, name);
  strcat(old, ":");
  strcat(old, value);
  arg_set_value(desc, "XREFS", strlen(old), old);
 }
 else 
  {
  char * str;
  
  str = emalloc(strlen(name) + strlen(value) + 2);
  strcat(str, name);
  strcat(str, ":");
  strcat(str, value);
  arg_add_value(desc, "XREFS", ARG_STRING, strlen(str), str);
  }
}

ExtFunc char * _plug_get_xref(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "XREFS");
}

ExtFunc char * plug_get_xref(struct arglist * desc)
{
 return store_fetch_xref(desc);
}



ExtFunc
void plug_set_family(desc, family, language)
 struct arglist * desc; 
 const char * family;
 const char * language;
{
  char * s_language;
  struct arglist * prefs = arg_get_value(desc, "preferences");
  
  s_language = arg_get_value(prefs,"language");
  if(s_language && language)
   {
    if(!strcmp(s_language, language))
    {
    if(family)
    arg_add_value(desc, "FAMILY", ARG_STRING,
    			strlen(family), estrdup(family));
    }
   }
  else if(family)
    {
     if(!arg_get_value(desc, "FAMILY"))
      arg_add_value(desc, "FAMILY", ARG_STRING,
    			strlen(family), estrdup(family));
    }
}


ExtFunc
char * _plug_get_family(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "FAMILY");
}

ExtFunc
char * plug_get_family(desc)
 struct arglist * desc;
{
 return store_fetch_family(desc);
}


ExtFunc
void plug_require_key(desc, keyname)
 struct arglist * desc;
 const char * keyname;
{
 struct arglist * keys;
 if(keyname)
 {
  keys = arg_get_value(desc, "required_keys");
  if(!keys)
  {
   keys = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "required_keys", ARG_ARGLIST, -1, keys);
  }
  arg_add_value(keys, keyname,  ARG_INT, 0, (void*)1);
 }
}

ExtFunc 
struct arglist * _plug_get_required_keys(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "required_keys");
}


ExtFunc 
struct arglist * plug_get_required_keys(desc)
 struct arglist * desc;
{
 return _plug_get_required_keys(desc);
}


ExtFunc
void plug_exclude_key(desc, keyname)
 struct arglist * desc;
 const char * keyname;
{
 struct arglist * keys;
 if(keyname)
 {
  keys = arg_get_value(desc, "excluded_keys");
  if(!keys)
  {
   keys = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "excluded_keys", ARG_ARGLIST, -1, keys);
  }
  arg_add_value(keys, keyname, ARG_INT, 0, (void*)1);
 }
}

ExtFunc
struct arglist * _plug_get_excluded_keys(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "excluded_keys");
}


ExtFunc
struct arglist * plug_get_excluded_keys(desc)
 struct arglist * desc;
{
 return _plug_get_excluded_keys(desc);
}

ExtFunc 
void plug_require_port(desc, portname)
 struct arglist * desc;
 const char * portname;
{
 struct arglist * ports;
 
 if(portname != NULL)
 {
  ports = arg_get_value(desc, "required_ports");
  if(!ports)
  {
   ports = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "required_ports", ARG_ARGLIST, -1, ports);
  }
  
  arg_add_value(ports, portname, ARG_INT, 0, (void*)1);
 }
}

ExtFunc
struct arglist * _plug_get_required_ports(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "required_ports");
}

ExtFunc
struct arglist * plug_get_required_ports(desc)
 struct arglist * desc;
{
 return _plug_get_required_ports(desc);
}


ExtFunc 
void plug_require_udp_port(desc, portname)
 struct arglist * desc;
 const char * portname;
{
 struct arglist * ports;
 
 if(portname != NULL)
 {
  ports = arg_get_value(desc, "required_udp_ports");
  if(!ports)
  {
   ports = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "required_udp_ports", ARG_ARGLIST, -1, ports);
  }
  
   arg_add_value(ports, portname, ARG_INT, 0, (void*)1);
 }
}

ExtFunc 
struct arglist * _plug_get_required_udp_ports(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "required_udp_ports");
}

ExtFunc 
struct arglist * plug_get_required_udp_ports(desc)
 struct arglist * desc;
{
 return _plug_get_required_udp_ports(desc);
}
 


ExtFunc
void plug_set_dep(desc, depname)
 struct arglist * desc;
 const char * depname;
{
 struct arglist * deps;
 if(depname)
 {
  deps = arg_get_value(desc, "DEPENDENCIES");
  if(!deps){
   deps = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "DEPENDENCIES", ARG_ARGLIST, -1, deps);
   }
  arg_add_value(deps, depname, ARG_STRING, 0, estrdup(""));
 }
}



ExtFunc
struct arglist * _plug_get_deps(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "DEPENDENCIES");
}


ExtFunc
struct arglist * plug_get_deps(desc)
 struct arglist * desc;
{
 return _plug_get_deps(desc);
#if 0
 return store_fetch_dependencies(desc);
#endif
}

ExtFunc
void plug_set_timeout(desc, timeout)
 struct arglist * desc; 
 int timeout;
{
    arg_add_value(desc, "TIMEOUT", ARG_INT, sizeof(int), (void *)timeout);
}


ExtFunc
int _plug_get_timeout(desc)
 struct arglist * desc;
{
 return (int)arg_get_value(desc, "TIMEOUT");
}


ExtFunc
int plug_get_timeout(desc)
 struct arglist * desc;
{
 return _plug_get_timeout(desc);
#if 0
 return store_fetch_timeout(desc);
#endif
}

		

ExtFunc
void plug_set_launch(desc, launch)
 struct arglist * desc;
 int launch;
{
  if(arg_set_value(desc, "ENABLED", sizeof(int), (void *)launch))
  {
   arg_add_value(desc, "ENABLED", ARG_INT, sizeof(int), (void *)launch);
  }
}


ExtFunc
int plug_get_launch(desc)
 struct arglist * desc;
{
 	return((int)arg_get_value(desc, "ENABLED"));
}	
	
	
ExtFunc
void plug_set_name(desc, name, language)
 struct arglist * desc; 
 const char * name; 
 const char * language;
{
 char * s_language;
 struct arglist * prefs = arg_get_value(desc, "preferences");
  
  s_language = arg_get_value(prefs,"language");
  if(s_language && language)
   {
    if(!strcmp(s_language, language))
    {
    if(name)
    arg_add_value(desc, "NAME", ARG_STRING,
    			strlen(name), estrdup(name));
    }
   }
  else if(name)
  {
    if(!arg_get_value(desc, "NAME"))
    	arg_add_value(desc, "NAME", ARG_STRING,
    			strlen(name), estrdup(name));	
  }
}

ExtFunc
char * _plug_get_name(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "NAME");
}

ExtFunc
char * plug_get_name(desc)
 struct arglist * desc;
{
 return _plug_get_name(desc);
 /*return store_fetch_name(desc);*/
}


ExtFunc
void plug_set_summary(desc, summary,language)
 struct arglist * desc;
 const char * summary;
 const char * language;
{
 char * s_language;
 struct arglist * prefs = arg_get_value(desc, "preferences");
  
  s_language = arg_get_value(prefs,"language");
  if(s_language && language)
   {
    if(!strcmp(s_language, language))
    {
    if(summary)
    arg_add_value(desc, "SUMMARY", ARG_STRING,
    			strlen(summary), estrdup(summary));
    }
   }
  else if(summary)
  {
    if(!arg_get_value(desc, "SUMMARY"))
    	arg_add_value(desc, "SUMMARY", ARG_STRING,
    			strlen(summary), estrdup(summary));	
  }
}

ExtFunc
char * _plug_get_summary(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "SUMMARY");
}

ExtFunc
char * plug_get_summary(desc)
 struct arglist * desc;
{
 return store_fetch_summary(desc);
}


ExtFunc
void plug_set_description(desc, description,language)
 struct arglist * desc;
 const char * description;
 const char * language;
{
  char * s_language;
 struct arglist * prefs = arg_get_value(desc, "preferences");
  
  s_language = arg_get_value(prefs,"language");
  if(s_language && language)
   {
    if(!strcmp(s_language, language))
    {
    if(description)
    arg_add_value(desc, "DESCRIPTION", ARG_STRING,
    			strlen(description), estrdup(description));
    }
   }
  else if(description)
  {
    if(!arg_get_value(desc, "DESCRIPTION"))
    	arg_add_value(desc, "DESCRIPTION", ARG_STRING,
    			strlen(description), estrdup(description));	
  }
}


ExtFunc
char * _plug_get_description(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "DESCRIPTION");
}

ExtFunc
char * plug_get_description(desc)
 struct arglist * desc;
{
 return store_fetch_description(desc);
}


ExtFunc
void plug_set_copyright(desc, copyright,language)
 struct arglist * desc;
 const char * copyright;
 const char * language;
{
 char * s_language;
 struct arglist * prefs = arg_get_value(desc, "preferences");
  
  s_language = arg_get_value(prefs,"language");
  if(s_language && language)
   {
    if(!strcmp(s_language, language))
    {
    if(copyright)
    arg_add_value(desc, "COPYRIGHT", ARG_STRING,
    			strlen(copyright), estrdup(copyright));
    }
   }
  else if(copyright)
  {
    if(!arg_get_value(desc, "COPYRIGHT"))
    	arg_add_value(desc, "COPYRIGHT", ARG_STRING,
    			strlen(copyright), estrdup(copyright));	
  }
}

ExtFunc
char * _plug_get_copyright(desc)
 struct arglist * desc;
{
 return arg_get_value(desc, "COPYRIGHT");
}


ExtFunc
char * plug_get_copyright(desc)
 struct arglist * desc;
{
 return store_fetch_copyright(desc);
}


ExtFunc
void plug_set_category(desc, category)
 struct arglist * desc;
 int category;
{
       arg_add_value(desc, "CATEGORY", ARG_INT, sizeof(int), (void *)category);
}

ExtFunc
int _plug_get_category(desc)
 struct arglist * desc;
{
 return (int)arg_get_value(desc, "CATEGORY");	/* We don't cache this one */
}

ExtFunc
int plug_get_category(desc)
 struct arglist * desc;
{
 return _plug_get_category(desc);
}



ExtFunc
void plug_add_host(desc, hostname)
 struct arglist * desc;
 struct arglist * hostname;
{
	struct arglist * h;
	
	h = arg_get_value(desc, "HOSTNAME");
	if(!h)arg_add_value(desc, "HOSTNAME", ARG_ARGLIST, sizeof(hostname), hostname);
	else arg_set_value(desc, "HOSTNAME", sizeof(hostname), hostname);
}


ExtFunc
void host_add_port_proto(args, portnum, state, proto)
 struct arglist * args;
 int portnum;
 int state;
 char * proto;
{
 char port_s[255];
 
 snprintf(port_s, sizeof(port_s), "Ports/%s/%d", proto, portnum);
 plug_set_key(args, port_s, ARG_INT, (void*)1);
}


ExtFunc
void host_add_port(hostdata, portnum, state)
 struct arglist * hostdata;
 int portnum;
 int state;
{
 host_add_port_proto(hostdata, portnum, state, "tcp");
}

ExtFunc
void host_add_port_udp(hostdata, portnum, state)
 struct arglist * hostdata;
 int portnum;
 int state;
{
 host_add_port_proto(hostdata, portnum, state, "udp");
}
  

int port_in_ports(port, ports, s, e)
	u_short port, * ports;
	int s, e;
{
 int mid = (s+e)/2;
 if(s==e)return(port == ports[e]);
 if(port > ports[mid])return(port_in_ports(port, ports, mid+1, e));
 else return(port_in_ports(port, ports, s, mid));
}
 	


static int
unscanned_ports_as_closed(prefs)
 struct arglist * prefs;
{
 char * unscanned;
 unscanned = arg_get_value(prefs, "unscanned_closed");
 if(unscanned && !strcmp(unscanned, "yes"))
  return 0;
 else
  return 1;
}
           
ExtFunc
int kb_get_port_state_proto(kb, prefs, portnum, proto)
 struct kb_item ** kb;
 struct arglist * prefs;
 int portnum;
 char * proto;
{ 
 char port_s[255];
 unsigned short * range;
 char * prange = (char*)arg_get_value(prefs, "port_range");
 int num;

 if(!proto)
  proto = "tcp";
  
 /* Check that we actually scanned the port */
 
 if(!strcmp(proto, "tcp") && kb_item_get_int(kb, "Host/scanned") <= 0){
	return unscanned_ports_as_closed(prefs);
	}

 else if(!strcmp(proto, "udp") && kb_item_get_int(kb, "Host/udp_scanned") <= 0)
       {
        return 1;
      }
      
      		
 range = (u_short*)getpts(prange, &num);

 if( range == NULL ){
 	return(1);
	}
	
 if(!port_in_ports(portnum, range, 0, num)){
       return unscanned_ports_as_closed(prefs);
       }
 
 /* Ok, we scanned it. What is its state ? */
 
 snprintf(port_s, sizeof(port_s), "Ports/%s/%d", proto, portnum);
 if(kb_item_get_int(kb, port_s) > 0 )
    return 1;
  else
   return 0;
}

ExtFunc
int host_get_port_state_proto(plugdata, portnum, proto)
 struct arglist * plugdata;
 int portnum;
 char * proto;
{ 
 struct kb_item ** kb = plug_get_kb(plugdata);
 struct arglist * prefs = arg_get_value(plugdata, "preferences");
 
 return kb_get_port_state_proto(kb, prefs, portnum, proto);
}

ExtFunc
int host_get_port_state(plugdata, portnum)
 struct arglist * plugdata;
 int portnum;
{
 return(host_get_port_state_proto(plugdata, portnum, "tcp"));
}

ExtFunc
int host_get_port_state_udp(plugdata, portnum)
 struct arglist * plugdata;
 int portnum;
{
 return(host_get_port_state_proto(plugdata, portnum, "udp"));
}


ExtFunc
const char * plug_get_hostname(desc)
 struct arglist * desc;
{
 struct arglist * hinfos = arg_get_value(desc, "HOSTNAME");
 if(hinfos)return((char*)arg_get_value(hinfos, "NAME"));
 else return(NULL);
}

ExtFunc
const char * plug_get_host_fqdn(desc)
 struct arglist * desc;
{
 struct arglist * hinfos = arg_get_value(desc, "HOSTNAME");
 if(hinfos)return((char*)arg_get_value(hinfos, "FQDN"));
 else return(NULL);
}


ExtFunc
struct in_addr * plug_get_host_ip(desc)
 struct arglist * desc;
{
 struct arglist * hinfos = arg_get_value(desc, "HOSTNAME");
 if(hinfos)return((struct in_addr*)arg_get_value(hinfos, "IP"));
 else return(NULL);
}



static void 
mark_successful_plugin(desc)
 struct arglist * desc;
{
 int id = plug_get_id(desc);
 char data[512];
 

 bzero(data, sizeof(data));
 snprintf(data, sizeof(data), "Success/%d", id);
 plug_set_key(desc, data, ARG_INT,(void*)1);
}

static void
mark_post(desc, action, content)
 struct arglist * desc;
 char * action;
 char * content;
{
 char entry_name[255];
 
 if(strlen(action) > (sizeof(entry_name) - 20))
  return;
  
 snprintf(entry_name, sizeof(entry_name), "SentData/%d/%s", plug_get_id(desc), action);
 plug_set_key(desc, entry_name, ARG_STRING, content);
}

 
 
/* Pluto 24.6.00: reduced to one, and left the orig in place */
void 
proto_post_wrapped(desc, port, proto, action, what)
 struct arglist * desc;
 int port;
 const char * proto;
 const char * action;
 const char * what;
{

 char *t;
 char * buffer;
 int soc;
 char * naction;
 int len;
 ntp_caps* caps = arg_get_value(desc, "NTP_CAPS");
 char * cve;
 char * bid;
 char * xref;
 int do_send = 1;
 int i;
 char ack;
 int n = 0, e, l;
  
    
 if( action == NULL )action = plug_get_description(desc);
 
 
 cve = plug_get_cve_id(desc);
 bid = plug_get_bugtraq_id(desc);
 xref = plug_get_xref(desc);
 
 if( action == NULL )
 	return;
	
	
 len = strlen(action) + 1;
 if(cve != NULL)
 	len += strlen(cve) + 20;

 if(bid != NULL)
  	len += strlen(bid) + 20;
	
 if(xref != NULL )
 	len += strlen(xref) + 20;
	
 if( caps == NULL )
 	return;

 
 naction = emalloc(len+1);
 strncpy(naction, action, strlen(action));
 strcat(naction, "\n");
 if( cve != NULL && cve[0] != '\0')
        {
	 strcat(naction, "CVE : ");
	 strcat(naction, cve);
	 strcat(naction, "\n");
	 }
 
 if( bid != NULL && bid[0] != '\0' )
 	{
	 strcat(naction, "BID : ");
	 strcat(naction, bid);
	 strcat(naction, "\n");
	 }	
 if( xref != NULL && xref[0] != '\0' )
 	{
	strcat(naction, "Other references : ");
	strcat(naction, xref);
	strcat(naction, "\n");
	}
 
 if( caps->escape_crlf == 0 )
   while((t=strchr(naction, '\n'))||(t=strchr(naction, '\r')))t[0]=';';
 else
  {
   char * old = naction;
   len -= strlen(naction);
   naction = addslashes(naction);
   len += strlen(naction);
   efree(&old);
  }
  
 for(i=0;naction[i];i++)
 {
   if(!isprint(naction[i]))
     	naction[i] = ' ';
 }


 buffer = emalloc( 1024 + len );
 if(caps->ntp_11) {
   char idbuffer[32];
   const char	*svc_name = nessus_get_svc_name(port, proto);
   if (caps->scan_ids) { 
     if (plug_get_id(desc) == 0) {
       *idbuffer = '\0';
     } else {
       int id = plug_get_id(desc);
       snprintf(idbuffer, sizeof(idbuffer), "<|> %d ", id);
     }
   } else {
     *idbuffer = '\0';
 }
  if(port>0){
     snprintf(buffer, 1024 + len, 
	     "SERVER <|> %s <|> %s <|> %s (%d/%s) <|> %s %s<|> SERVER\n",
	     what,
  	     plug_get_hostname(desc),
	     svc_name,
	     port, proto, naction, idbuffer);
    
   } else
     snprintf(buffer, 1024 + len, 
	     "SERVER <|> %s <|> %s <|> general/%s <|> %s %s<|> SERVER\n",
	     what,
  	     plug_get_hostname(desc), 
	     proto, naction, idbuffer);
 } else {
   snprintf(buffer, 1024 + len, "SERVER <|> %s <|> %s <|> %d:%s <|> SERVER\n", 
	   what,
	   plug_get_hostname(desc), port, naction);
 }
 
 

mark_post(desc, what, action); 
soc = (int)arg_get_value(desc, "SOCKET");
internal_send(soc, buffer, INTERNAL_COMM_MSG_TYPE_DATA);
 
 /*
  * Mark in the KB that the plugin was sucessful
  */
 mark_successful_plugin(desc);
 efree(&buffer);
 efree(&naction);
 return;
}

/* Pluto end */

ExtFunc
void proto_post_hole(desc, port, proto, action)
 struct arglist * desc;
 int port;
 const char * proto;
 const char * action;
{
  proto_post_wrapped(desc, port, proto, action, "HOLE");
  return;
}


ExtFunc
void post_hole(desc, port, action)
 struct arglist * desc;
 int port;
 const char * action;
{
  proto_post_hole(desc, port, "tcp", action);
} 


ExtFunc
void post_hole_udp(desc, port, action)
 struct arglist * desc;
 int port;
 const char * action;
{
 proto_post_hole(desc, port, "udp", action);
}


ExtFunc
void post_info(desc, port, action)
 struct arglist * desc;
 int port;
 const char * action;
{
  proto_post_info(desc, port, "tcp", action);
} 


ExtFunc
void post_info_udp(desc, port, action)
 struct arglist * desc;
 int port;
 const char * action;
{
 proto_post_info(desc, port, "udp", action);
}


ExtFunc
void proto_post_info(desc, port, proto, action)
 struct arglist * desc;
 int port;
 const char * proto;
 const char * action;
{
  proto_post_wrapped(desc, port, proto, action, "INFO");
  return;
}
 
ExtFunc
void post_note(desc, port, action)
 struct arglist * desc;
 int port;
 const char * action;
{
#if 0
  fprintf(stderr, "Post_note: port = %d action = %s\n", port, action);
#endif
  proto_post_note(desc, port, "tcp", action);
} 

     
ExtFunc
void post_note_udp(desc, port, action)
 struct arglist * desc;
 int port;
 const char * action;
{
 proto_post_note(desc, port, "udp", action);
}
	   

ExtFunc
void proto_post_note(desc, port, proto, action)
 struct arglist * desc;
 int port;
 const char * proto;
 const char * action;
{
  /*
   * Backward compatibility. We only use the notes if the remote
   * client accepts them
   */
  char * allow_notes = get_preference(desc, "ntp_client_accepts_notes");
  if(allow_notes && !strcmp(allow_notes, "yes")) 
   proto_post_wrapped(desc, port, proto, action, "NOTE");
  else
   proto_post_wrapped(desc, port, proto, action, "INFO");
 return;
} 
 
 
ExtFunc
char * get_preference(desc, name)
 struct arglist *desc;
 const char * name;
{
 struct arglist * prefs;
 prefs = arg_get_value(desc, "preferences");
 if(!prefs)return(NULL);
 return((char *)arg_get_value(prefs, name));
}


ExtFunc
void _add_plugin_preference(prefs, p_name, name, type, defaul)
 struct arglist *prefs;
 const char * p_name;
 const char * name;
 const char * type;
 const char * defaul;
{
 char * pref;
 char * cname;
 int len;
 
 
 
 cname = estrdup(name);
 len = strlen(cname);
 while(cname[len-1]==' ')
 {
  cname[len-1]='\0';
  len --;
 }
 if(!prefs || !p_name)
   {
     efree(&cname);
     return;
   }


 pref = emalloc(strlen(p_name)+10+strlen(type)+strlen(cname));
 sprintf(pref, "%s[%s]:%s", p_name, type, cname);
 if ( arg_get_value(prefs, pref) == NULL )
  arg_add_value(prefs, pref, ARG_STRING, strlen(defaul), estrdup(defaul));

 efree(&cname);
 efree(&pref);
}

void add_plugin_preference(desc, name, type, defaul)
 struct arglist *desc;
 const char * name;
 const char * type;
 const char * defaul;
{
 struct arglist * prefs = arg_get_value(desc, "PLUGIN_PREFS");
 char pref[1024];
 
 
 if(prefs == NULL)
  {
   prefs = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "PLUGIN_PREFS", ARG_ARGLIST, -1, prefs);
  }
 

 snprintf(pref, sizeof(pref), "%s/%s", type, name);
 arg_add_value(prefs, pref, ARG_STRING, strlen(defaul), estrdup(defaul));
}



ExtFunc char * 
get_plugin_preference(desc, name)
  struct arglist * desc;
  const char * name;
{
 struct arglist * prefs = arg_get_value(desc, "preferences");
 char * plug_name = plug_get_name(desc);
 char * cname = estrdup(name);
 int len;
 
 len = strlen(cname);
 
 while(cname[len-1]==' ')
 {
  cname[len-1]='\0';
  len --;
 }
 
 
 if(!prefs)
   {
     efree(&cname);
     return NULL;
   }
  
 while(prefs->next)
 {
  char * a= NULL, *b = NULL;
  int c = 0;
  char * t = prefs->name;
  
  a = strchr(t, '[');
  if(a)b=strchr(t, ']');
  if(b)c=(b[1]==':');
  
  if(c)
  {
   b+=2*sizeof(char);
   if(!strcmp(cname, b)){
   	int old = a[0];
   	a[0] = 0;
	if(!strcmp(t, plug_name)){
		a[0] = old;
		efree(&cname);
		return(prefs->value);
		}
	a[0] = old;	
	}
  }
  prefs = prefs->next;
 }
 efree(&cname);
 return(NULL);
}

ExtFunc const char * 
get_plugin_preference_fname(desc, filename)
 struct arglist * desc;
 const char * filename;
{
 struct arglist * globals = arg_get_value(desc, "globals");
 harglst * trans;
 if(!globals) 
  return NULL;
  
 trans = arg_get_value(globals, "files_translation");
 if(!trans)
  return NULL;
 
 return harg_get_string(trans, filename);
}


void * plug_get_fresh_key(args, name, type)
 struct arglist * args;
 char * name;
 int * type;
{
 struct arglist * globals = arg_get_value(args, "globals");
 int soc = (int)arg_get_value(globals, "global_socket");
 int e;
 char * buf = NULL;
 int bufsz = 0;
 int msg;
 
 if ( name == NULL || type == NULL ) return NULL;
 *type = -1;

 e = internal_send(soc, name, INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_GET);
 if(e < 0){
        fprintf(stderr, "[%d] plug_get_fresh_key:internal_send(%d): %s\n",getpid(), soc,name, strerror(errno));
	goto err;
	}

 internal_recv(soc, &buf, &bufsz, &msg); 
 if ( ( msg & INTERNAL_COMM_MSG_TYPE_KB ) == 0  )
 {
        fprintf(stderr, "[%d] plug_get_fresh_key:internal_send(%d): Unexpected message %d",getpid(), soc, msg);
	goto err;
 }

 if ( msg & INTERNAL_COMM_KB_ERROR ) return NULL;
 if ( msg & INTERNAL_COMM_KB_SENDING_STR )
 {
  char * ret = estrdup(buf);
  *type = ARG_STRING;
  efree(&buf);
  return ret;
 } 
 else if ( msg & INTERNAL_COMM_KB_SENDING_INT )
 {
  int ret;
  *type = ARG_INT;
  ret = atoi(buf);
  efree(&buf);
  return (void*)ret;
 }
err:
 if ( buf != NULL )efree(&buf);
 return NULL; 
} 

static void plug_set_replace_key(args, name, type, value, replace)
 struct arglist * args;
 char * name;
 int type;
 void * value;
 int replace;
{
 struct kb_item ** kb = plug_get_kb(args);
 struct arglist * globals = arg_get_value(args, "globals");
 int soc = (int)arg_get_value(globals, "global_socket");
 char * str = NULL;
 int msg;
 
 
#ifdef DEBUG
 printf("set key %s -> %d\n", name, value);
#endif 
 
 if( name == NULL || value == NULL )return;
 
 switch(type)
 {
  case ARG_STRING :
   kb_item_add_str(kb, name, value);
   value = addslashes(value);
   str = emalloc(strlen(name)+strlen(value)+10);
   sprintf(str, "%d %s=%s;\n", ARG_STRING, name, (char *)value);
   efree(&value);
   break;
  case ARG_INT :
   kb_item_add_int(kb, name, (int)value);
   str = emalloc(strlen(name)+20);
   sprintf(str, "%d %s=%d;\n", ARG_INT, name, (int)value);
   break;
 }
 if(str)
 {
   int e;
   if ( replace != 0 )
    msg = INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_REPLACE;
   else
    msg = INTERNAL_COMM_MSG_TYPE_KB;

   e = internal_send(soc, str, msg);
    if(e < 0){
        fprintf(stderr, "[%d] plug_set_key:internal_send(%d)['%s']: %s\n",getpid(), soc,str, strerror(errno));
	}
   efree(&str);
  }
} 


ExtFunc void plug_set_key(args, name, type, value)
 struct arglist * args;
 char * name;
 int type;
 void * value;
{
 plug_set_replace_key(args, name, type, value, 0);
}


ExtFunc void plug_replace_key(args, name, type, value)
 struct arglist * args;
 char * name;
 int type;
 void * value;
{
 plug_set_replace_key(args, name, type, value, 1);
}
ExtFunc void
scanner_add_port(args, port, proto)
 struct arglist * args;
 int port;
 char * proto;
{
 ntp_caps* caps = arg_get_value(args, "NTP_CAPS");
 char * buf;
 const char *svc_name = nessus_get_svc_name(port, proto);
 const char * hn = plug_get_hostname(args);
 int len;
 int soc;
 struct arglist * globs;
 int do_send = 1;
 static int confirm = -1;
 
 if(confirm < 0)
 {
  struct arglist * globals = arg_get_value(args, "globals");
  if(globals)confirm = (int)arg_get_value(globals, "confirm");
 }

 /*
  * Diff scan stuff : if the port was known to be open,
  * there is no need to report it again.
  */
 if(arg_get_value(args, "DIFF_SCAN"))
 {
   char port_s[255];
   snprintf(port_s, sizeof(port_s), "Ports/%s/%d", proto, port);
   if(kb_item_get_int(plug_get_kb(args), port_s) > 0) do_send = 0;
 }


 host_add_port_proto(args, port, 1, proto);
 
 len = 255 + (hn ? strlen(hn):0) + strlen(svc_name);
 buf = emalloc(len);
 if(caps != NULL && caps->ntp_11)
  snprintf(buf, len, "SERVER <|> PORT <|> %s <|> %s (%d/%s) <|> SERVER\n",
 		hn,svc_name, port, proto);
 else
  {
   if(!strcmp(proto, "tcp"))
     snprintf(buf, len, "SERVER <|> PORT <|> %s <|> %d <|> SERVER\n",
  		hn, port);
  }
   
 if(do_send)
 {
  soc = (int)arg_get_value(args, "SOCKET");
  internal_send(soc, buf, INTERNAL_COMM_MSG_TYPE_DATA);
 }
 efree(&buf);
}



struct kb_item ** plug_get_kb(struct arglist * args)
{
 return (struct kb_item**)arg_get_value(args, "key");
} 

/*
 * plug_get_key() may fork(). We use this signal handler to kill
 * its son in case the process which calls this function is killed
 * itself
 */
#ifndef NESSUSNT
static int _plug_get_key_son = 0;

static void 
plug_get_key_sighand_term(int sig)
{
 int son = _plug_get_key_son;
 
 if(son != 0)
 {
  kill(son, SIGTERM);
  _plug_get_key_son = 0;
 }
 _exit(0);
}

static void
plug_get_key_sigchld(int sig)
{
 int status;
 wait(&status);
}

static void
sig_n(int signo, void (*fnc)(int) )
{
 #ifdef HAVE_SIGACTION
  struct sigaction sa;
  sa.sa_handler = fnc;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(signo, &sa, (struct sigaction *) 0);
#else
  signal(signo, fnc);
#endif
}

static void
sig_term( void (*fcn)(int) )
{
 sig_n(SIGTERM, fcn);
}

static void
sig_alarm( void (*fcn)(int) )
{
 sig_n(SIGALRM, fcn);
}

static void 
sig_chld( void(*fcn)(int) )
{
 sig_n(SIGCHLD, fcn);
}
#endif


void * 
plug_get_key(args, name, type)
 struct arglist * args;
 char * name;
 int * type;
{
 struct kb_item ** kb = plug_get_kb(args);
 struct kb_item * res = NULL;
 int sockpair[2];
 int upstream = 0;
 char * buf = NULL;
 int bufsz = 0;
 
 
 if ( type != NULL )
	*type = -1;
 
 
 if( kb == NULL )
    return NULL;

 res = kb_item_get_all(kb, name);
 
 if ( res == NULL ) 
    return NULL;

 if ( res->next == NULL ) /* No fork - good */
 {
  void * ret;
  if(res->type == KB_TYPE_INT)
    {
    if( type != NULL ) *type = ARG_INT;
    ret   = (void*)res->v.v_int;
    }
  else
    {
    if(type != NULL)*type = ARG_STRING;
    ret   = (void*)res->v.v_str;
    } 
  kb_item_get_all_free(res);
  return ret;
 }
 
 
 /* More than  one value - we will fork() then */
 sig_chld(plug_get_key_sigchld);
 while( res != NULL )
 {
  pid_t pid;
  socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair);
  if ( (pid = fork()) == 0 )
  {
   int tictac = 0;
   int old, soc;
   struct arglist * globals, * preferences = NULL;
  
   close(sockpair[0]);  
   globals = arg_get_value(args, "globals");  
   old = (int)arg_get_value(globals, "global_socket");
   close(old);
   soc = dup2(sockpair[1], 4);
   close(sockpair[1]);
   arg_set_value(globals, "global_socket", sizeof(int), (void*)soc);
   arg_set_value(args, "SOCKET", sizeof(int), (void*)soc);

   if ( globals != NULL ) preferences = arg_get_value(globals, "preferences");
   if ( preferences != NULL )
   { 
    char * to = arg_get_value(preferences, "plugins_timeout");
    if ( to != NULL )  tictac = atoi(to);
   }

   srand48(getpid() + getppid() + time(NULL));
 
   sig_term(_exit);
   sig_alarm(_exit);
   alarm(120);


   if ( res->type == KB_TYPE_INT )
   {
    int old_value = res->v.v_int;
     kb_item_rm_all(kb, name); 
     kb_item_add_int(kb, name, old_value);
    if ( type != NULL )*type = ARG_INT;
    return (void*)old_value;
   }
   else
   {
    char * old_value = estrdup(res->v.v_str);
    kb_item_rm_all(kb, name); 
    kb_item_add_str(kb, name, old_value);
    if ( type != NULL ) *type = ARG_STRING;
    efree(&old_value);
    return kb_item_get_str(kb, name);
   }
  }
  else if(pid < 0)
      {
       fprintf(stderr, "nessus-libraries:libnessus:plugutils.c:plug_get_key(): fork() failed : %s", strerror(errno));	      
       return NULL;
      }
  else
      {
      int e;
      int status;
      struct arglist * globals, * preferences = NULL;
  
      globals = arg_get_value(args, "globals");  
      upstream = (int)arg_get_value(globals, "global_socket");
      close(sockpair[1]);
      _plug_get_key_son = pid;
      sig_term(plug_get_key_sighand_term);
      for(;;)
      {
      fd_set rd;
      struct timeval tv;
      int type;
      do {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
      FD_ZERO(&rd);
      FD_SET(sockpair[0], &rd);
      e = select ( sockpair[0] + 1, &rd, NULL, NULL, &tv);
      } while ( e < 0 && errno == EINTR );
      
      if ( e > 0 )
      {
       e = internal_recv(sockpair[0], &buf, &bufsz, &type);
       if (e < 0 || ( type & INTERNAL_COMM_MSG_TYPE_CTRL ) )
	{
         e = waitpid(pid,&status,WNOHANG);
         _plug_get_key_son = 0;
         close(sockpair[0]);
         sig_term(_exit);
	 break;
	}
       else internal_send(upstream, buf, type);
      }
     }
     }
   res = res->next;
   }
   internal_send(upstream, NULL, INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
   exit(0);
}

/*
 * Don't always return the first open port, otherwise
 * we might get bitten by OSes doing active SYN flood
 * countermeasures. Also, avoid returning 80 and 21 as
 * open ports, as many transparent proxies are acting for these...
 */
ExtFunc unsigned int
plug_get_host_open_port(struct arglist * desc)
{
 struct kb_item ** kb = plug_get_kb(desc);
 char * t;
 int port = 0;
 struct kb_item * res, *k;
 int open21 = 0, open80 = 0;
#define MAX_CANDIDATES 16
 u_short candidates[MAX_CANDIDATES];
 int num_candidates = 0;
 
 k = res = kb_item_get_pattern(kb, "Ports/tcp/*");
 if ( res == NULL ) 
    return 0;
 else 
    {
     int ret;
     char * s;
 
     for(;;)
     {
      s = res->name + sizeof("Ports/tcp/") - 1;
      ret = atoi(s);
      if ( ret == 21 ) open21 = 1;
      else if ( ret == 80 ) open80 = 1;
      else  {
                candidates[num_candidates++] = ret;
                if ( num_candidates >= MAX_CANDIDATES ) break;
	    }
      res = res->next;
      if ( res == NULL ) break;
     }

     kb_item_get_all_free(k);
     if ( num_candidates != 0 )
       return candidates[lrand48() % num_candidates];
     else  
          if (open21) return 21;
     else  
          if (open80) return 80;
     else  
          return 0;
    }

 /* Not reachable */
 return 0;
}


       
 
/*
 * Those brain damaged functions should probably be in another file
 * They are use to remember who speaks SSL or not
 */
   
ExtFunc
void plug_set_port_transport(args, port, tr)
     struct arglist * args;
     int		port, tr;
{
  char	s[256];

  snprintf(s, sizeof(s), "Transports/TCP/%d", port);
  plug_set_key(args, s, ARG_INT, (void*)tr);
}

ExtFunc
int plug_get_port_transport(args, port)
     struct arglist * args;
     int		port;
{
  char	s[256];
  int trp;
  
  snprintf(s, sizeof(s), "Transports/TCP/%d", port);
  trp = kb_item_get_int(plug_get_kb(args), s);
  if (trp >= 0)
    return trp;
  else 
    return NESSUS_ENCAPS_IP; /* Change this to 0 for ultra smart SSL negotiation, at the expense
                                of possibly breaking stuff */
}

ExtFunc
const char* plug_get_port_transport_name(args, port)
     struct arglist * args;
     int		port;
{
  return get_encaps_name(plug_get_port_transport(args, port));
}

#ifdef HAVE_SSL
static void
plug_set_ssl_item(args, item, itemfname)
 struct arglist * args;
 char * item;
 char * itemfname;
{
 char s[256];
 snprintf(s, sizeof(s), "SSL/%s", item);
 plug_set_key(args, s, ARG_STRING, itemfname);
}

ExtFunc void
plug_set_ssl_cert(args, cert)
 struct arglist * args;
 char * cert;
{
 plug_set_ssl_item(args, "cert", cert);
}

ExtFunc void 
plug_set_ssl_key(args, key)
 struct arglist * args;
 char * key;
{
 plug_set_ssl_item(args, "key", key);
}
ExtFunc void
plug_set_ssl_pem_password(args, key)
 struct arglist * args;
 char * key;
{
 plug_set_ssl_item(args, "password", key);
}

ExtFunc void
plug_set_ssl_CA_file(args, key)
 struct arglist * args;
 char * key;
{
 plug_set_ssl_item(args, "CA", key);
}
#else
ExtFunc  void
plug_set_ssl_cert(args, cert)
 struct arglist * args;
 char * cert;
{
 fprintf(stderr, "plug_set_ssl_cert(): not implemented\n");
}

ExtFunc void
plug_set_ssl_key(args, key)
 struct arglist * args;
 char * key;
{
 fprintf(stderr, "plug_set_ssl_key(): not implemented\n");
}
#endif /* HAVE_SSL */


ExtFunc char *
find_in_path(name, safe)
     char	*name;
     int	safe;
{
  char		*buf = getenv("PATH"), *pbuf, *p1, *p2;
  static char	cmd[MAXPATHLEN];
  int		len = strlen(name);
  
  if (len >= MAXPATHLEN)
    return NULL;

#if 0
  /* Proposed by Devin Kowatch 
     If it's already an absolute path take it as is */
  if (name[0] == '/' && access(name, X_OK) == 0)
    return name;	/* Invalid: we should remove everything after the last / */
#endif

  if (buf == NULL)		/* Should we use a standard PATH here? */
    return NULL;

  pbuf = buf;
  while (*pbuf != '\0')
    {
      for (p1 = pbuf, p2 = cmd; *p1 != ':' && *p1 != '\0'; )
	*p2 ++ = *p1 ++;
      *p2 = '\0';
      if (*p1 == ':')
	p1 ++;
      pbuf = p1;
      if (p2 == cmd)		/* :: found in $PATH */
	strcpy(cmd, ".");

      if (cmd[0] != '/' && safe)
	continue;
      if (p2 - cmd + 1 + len >= MAXPATHLEN)
	/* path too long: cannot be reached */
	continue;

      sprintf(p2, "/%s", name);
      if (access(cmd, X_OK) == 0)
	{
	  struct stat	st;
	  if (stat(cmd, &st) < 0)
	    perror(cmd);
	  else if (S_ISREG(st.st_mode))
	    {
	      *p2 = '\0';
#if 0
	      fprintf(stderr, "find_in_path: %s found in %s\n", name, cmd);
#endif
	      return cmd;
	    }
	}
#if 0
	  fprintf(stderr, "find_in_path: No %s\n", cmd);
#endif
    }
  return NULL;
}

ExtFunc int 
is_shell_command_present(name)
 char * name;
{
  return find_in_path(name, 0) != NULL;
}



ExtFunc int shared_socket_register ( struct arglist * args, int fd, char * name )
{
 int soc; 
 int type;
 unsigned int opt_len = sizeof(type);
 int e;  
 soc = (int)arg_get_value(args, "SOCKET");
 if ( fd_is_stream(fd) )
  fd = nessus_get_socket_from_connection(fd);


 e = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &opt_len);
 if ( e < 0 )
 {
  fprintf(stderr, "shared_socket_register(): Not a socket! - %s\n", strerror(errno));
  return -1;
 }

 internal_send(soc, name, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_REGISTER);
 internal_send(soc, NULL, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_DORECVMSG);
 send_fd(soc, fd);
 return 0;
}

ExtFunc int shared_socket_acquire ( struct arglist * args, char * name )
{
 int soc; 
 char * buf = NULL;
 int bufsz = 0;
 int msg;

 soc = (int)arg_get_value(args, "SOCKET");

 /* Wait forever until SHARED_SOCKET_ACQUIRE is true */
 for ( ;; )
 {
 if ( internal_send(soc, name, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_ACQUIRE) < 0 ) break;
 if ( internal_recv(soc, &buf, &bufsz, &msg) < 0 ) break;
 if ( ( msg & INTERNAL_COMM_MSG_SHARED_SOCKET) == 0 )
	{
	 fprintf(stderr, "[%d] shared_socket_acquire(): unexpected message - %d\n", getpid(), msg);
	 return -1;
	}
  if ( msg & INTERNAL_COMM_SHARED_SOCKET_ERROR )
	 return -1;
  else if ( msg & INTERNAL_COMM_SHARED_SOCKET_BUSY )
	 sleep(1);
  else if ( msg & INTERNAL_COMM_SHARED_SOCKET_DORECVMSG )
  {
   int fd = recv_fd(soc);
   return fd;
  }
 }

 /* Unreachable */
 return -1;
}
 

ExtFunc int shared_socket_release ( struct arglist * args, char * name )
{
 int soc; 

 soc = (int)arg_get_value(args, "SOCKET");
 return internal_send(soc, name, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_RELEASE);
}

ExtFunc int shared_socket_destroy ( struct arglist * args, char * name )
{
 int soc; 

 soc = (int)arg_get_value(args, "SOCKET");
 return internal_send(soc, name, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_DESTROY);
}
