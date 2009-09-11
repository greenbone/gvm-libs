/* OpenVAS
 * $Id$
 * Description: Plugin-specific stuff.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2003 Renaud Deraison
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#include <glib.h>

#include "arglists.h"
#include "comm.h"
#include "harglists.h"
#include "kb.h"
#include "network.h"
#include "rand.h"
#include "plugutils.h"
#include "services.h"
#include "share_fd.h"
#include "system.h"

/* want version stuff */
#include "libvers.h"
#include "scanners_utils.h"

/**
 * @brief Returns a static version string.
 * @return Version of openvas-libraries, do not modify nor free.
 */
char *
nessuslib_version()
{
  static char vers[255]; /* RATS: ignore, vers is used wisely. */
  strncpy (vers, VERSION, sizeof(vers) - 1);
  vers[sizeof(vers) - 1 ] = '\0';
  return vers;
}

/**
 * @brief Sets \ref major \ref minor and \rev to the respective values of the
 *        openvas-libraries version.
 */
void
nessus_lib_version (int* major, int* minor, int* rev)
{
 *major = OPENVASLIBS_MAJOR;
 *minor = OPENVASLIBS_MINOR;
 *rev   = OPENVASLIBS_REV;
}

#ifdef USE_PTHREADS
int
nessuslib_pthreads_enabled()
{
 int enabled = 1;
 return(enabled);
}
#endif




/**
 * @brief Escapes \\n and \\r and \\ in \<in\> properly. The
 * @brief resulting string is copied and returned.
 *
 * @param in String in which to escape \\n, \\r and \\.
 *
 * @return Copy of in with \\n, \\r and \\ escaped, NULL if @ref in is NULL.
 * 
 * @see To undo, call rmslashes.
 */
char *
addslashes (char* in)
{
 char * ret;
 char * out;

 if (in == NULL) return NULL;

 out = malloc (strlen(in) * 2 + 1);
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
  else
  {
    out[0] = in[0];
    out++;
  }
  in++;
 }
 return realloc(ret, strlen(ret) + 1);
}

/**
 * @brief Replaces escape codes (\\n, \\r) by the real value.
 * 
 * The resulting string is stored in another buffer.
 *
 * @see (slashes could have been added with addslashes)
 */
char *
rmslashes (char * in)
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


void
plug_set_version (struct arglist * desc, const char* version)
{
  if (version) 
    arg_add_value(desc, "VERSION", ARG_STRING, strlen(version), estrdup((char*)version));
}

char *
plug_get_version (struct arglist * desc)
{
 return arg_get_value(desc, "VERSION");
}

void
plug_set_path (struct arglist * desc, const char * path)
{
  if (path)
    arg_add_value(desc, "PATH", ARG_STRING, strlen(path), estrdup((char*)path));
}

char *
plug_get_path (struct arglist * desc)
{
 return arg_get_value(desc, "PATH");
}

void
plug_set_id (struct arglist * desc, int id)
{
 arg_add_value(desc, "ID", ARG_INT, sizeof(gpointer), GSIZE_TO_POINTER(id));
 /* If a script_id has been set then set a matching script_oid */
 char *oldid  = arg_get_value(desc, "OID");
 if (oldid != NULL)
 {
  oldid = erealloc(oldid, strlen(LEGACY_OID) + (sizeof(id) * 3) + 1);
 }
 else
 {
  oldid = emalloc(strlen(LEGACY_OID) + (sizeof(id) * 3) + 1);
 }
 // RATS: ignore
 snprintf(oldid, 100, LEGACY_OID "%i", id);
 arg_add_value(desc, "OID", ARG_STRING, strlen(oldid), estrdup(oldid));
#ifdef DEBUG
 fprintf(stderr, "plug_set_id: Legacy plugin %i detected\n", id);
#endif
}

int
plug_get_id (struct arglist * desc)
{
 return GPOINTER_TO_SIZE(arg_get_value(desc, "ID"));
}

void
plug_set_oid (struct arglist * desc, char *id)
{
 int oldid = GPOINTER_TO_SIZE(arg_get_value(desc, "ID"));
 /* Only allow a scipt_oid to be set if no script_id has already been set */
 if (oldid <= 0)
 {
  arg_add_value(desc, "OID", ARG_STRING, strlen(id), estrdup(id));
 }
 else
 {
  fprintf(stderr, "plug_set_oid: Invalid script_oid call, legacy plugin %i detected\n", oldid);
 }
}

char *
plug_get_oid (struct arglist * desc)
{
  return arg_get_value(desc, "OID");
}

void
plug_set_cve_id (struct arglist * desc, char * id)
{
 char * old = arg_get_value(desc, "CVE_ID");

 if (! id) return;

 if(old != NULL)
 {
  old = erealloc(old, strlen(old) + strlen(id) + 3);
  strcat(old, ", "); /* RATS: ignore */
  /* Rid ff warnings */
  /* Stmt's valid since len(id)+len(old)+len('\0'+", ") = size of realloc'd memory*/
  strcat(old, id); /* RATS: ignore */ 
  arg_set_value(desc, "CVE_ID", strlen(old), old);
 }
 else
  arg_add_value(desc, "CVE_ID", ARG_STRING, strlen(id), estrdup(id));
}

char *
plug_get_cve_id (struct arglist * desc)
{
 return arg_get_value(desc, "CVE_ID");
}


void
plug_set_bugtraq_id (struct arglist * desc, char* id)
{
 char * old = arg_get_value(desc, "BUGTRAQ_ID");

 if (! id) return;

 if(old != NULL)
 {
  old = erealloc(old, strlen(old) + strlen(id) + 3);
  strcat(old, ", "); /* RATS: ignore */
  strcat(old, id); /* RATS: ignore */
  arg_set_value(desc, "BUGTRAQ_ID", strlen(old), old);
 }
 else
  arg_add_value(desc, "BUGTRAQ_ID", ARG_STRING, strlen(id), estrdup(id));
}

char *
plug_get_bugtraq_id (struct arglist * desc)
{
 return arg_get_value(desc, "BUGTRAQ_ID");
}

void
plug_set_xref (struct arglist * desc, char* name, char* value)
{
 char * old = arg_get_value(desc, "XREFS");
 if(old != NULL)
 {
  old = erealloc(old, strlen(old) + strlen(name) + strlen(value) + 4);
  strcat(old, ", "); /* RATS: ignore */
  strcat(old, name); /* RATS: ignore */
  strcat(old, ":"); /* RATS: ignore */
  strcat(old, value); /* RATS: ignore */
  arg_set_value(desc, "XREFS", strlen(old), old);
 }
 else
  {
  char * str;
  // g_strdup_printf
  str = emalloc(strlen(name) + strlen(value) + 2);
  strcat(str, name); /* RATS: ignore */ 
  strcat(str, ":");
  strcat(str, value); /* RATS: ignore */ 
  arg_add_value(desc, "XREFS", ARG_STRING, strlen(str), str);
  }
}

char *
plug_get_xref (struct arglist * desc)
{
 return arg_get_value(desc, "XREFS");
}

void
plug_set_tag (struct arglist * desc, char* name, char* value)
{
 char * old = arg_get_value(desc, "TAGS");
 if(old != NULL)
 {
  old = erealloc(old, strlen(old) + strlen(name) + strlen(value) + 3);
  strcat(old, "|");
  strcat(old, name); /* RATS: ignore */ 
  strcat(old, "=");
  strcat(old, value); /* RATS: ignore */ 
  arg_set_value(desc, "TAGS", strlen(old), old);
 }
 else
  {
  char * str;

  str = emalloc(strlen(name) + strlen(value) + 2);
  strcat(str, name); /* RATS: ignore */
  strcat(str, "=");
  strcat(str, value); /* RATS: ignore */
  arg_add_value(desc, "TAGS", ARG_STRING, strlen(str), str);
  }
}

char *
plug_get_tag (struct arglist * desc)
{
 return arg_get_value(desc, "TAGS");
}

/**
 * @brief Set string that lists signature keys for a plugin or add it, if not
 * @brief empty.
 *
 * Key-ids are stored as comma- seperated list ('ABCDEFGH,ABCDEFG1').
 *
 * @param desc Plugin as arglist.
 * @param key_ids Comma-separated fingerprints.
 */
void
plug_set_sign_key_ids (struct arglist* desc, char* key_ids)
{
  char* value = plug_get_sign_key_ids( desc );
  if (key_ids == NULL) return;
  if(value != NULL)
  {
    value = erealloc(value, strlen(value) + strlen(key_ids) + 2);
    strcat(value, ",");
    strcat(value, key_ids); /* RATS: ignore */ 
    arg_add_value(desc, "SIGN_KEY_IDS", ARG_STRING, strlen(value), value);
  }
  else
  {
    arg_add_value(desc, "SIGN_KEY_IDS", ARG_STRING, strlen(key_ids), 
                  estrdup(key_ids));
  }
}

/**
 * @brief Return pointer to the string that lists signature keys for a plugin.
 */
char*
plug_get_sign_key_ids (struct arglist* desc)
{
  return arg_get_value(desc, "SIGN_KEY_IDS");
}


void
plug_set_family (struct arglist * desc, const char* family)
{
  if(! family) return;

  arg_add_value(desc, "FAMILY", ARG_STRING,
                strlen(family), estrdup(family));
}

char *
plug_get_family (struct arglist * desc)
{
 return arg_get_value(desc, "FAMILY");
}


void
plug_require_key (struct arglist * desc, const char * keyname)
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


struct arglist *
plug_get_required_keys (struct arglist * desc)
{
  return arg_get_value(desc, "required_keys");
}

void
plug_mandatory_key (struct arglist * desc, const char * keyname)
{
 struct arglist * keys;
 if(keyname)
  {
    keys = arg_get_value(desc, "mandatory_keys");
    if(!keys)
      {
        keys = emalloc(sizeof(struct arglist));
        arg_add_value(desc, "mandatory_keys", ARG_ARGLIST, -1, keys);
      }
    arg_add_value(keys, keyname,  ARG_INT, 0, (void*)1);
  }
}


struct arglist *
plug_get_mandatory_keys (struct arglist * desc)
{
  return arg_get_value(desc, "mandatory_keys");
}

void
plug_exclude_key (struct arglist * desc, const char * keyname)
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

struct arglist *
plug_get_excluded_keys (struct arglist * desc)
{
  return arg_get_value(desc, "excluded_keys");
}

void
plug_require_port (struct arglist * desc, const char * portname)
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

struct arglist * plug_get_required_ports (struct arglist * desc)
{
  return arg_get_value(desc, "required_ports");
}


void
plug_require_udp_port (struct arglist * desc, const char * portname)
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

struct arglist * plug_get_required_udp_ports (struct arglist * desc)
{
  return arg_get_value(desc, "required_udp_ports");
}


void
plug_set_dep (struct arglist * desc, const char * depname)
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

struct arglist *
plug_get_deps (struct arglist * desc)
{
  return arg_get_value(desc, "DEPENDENCIES");
}

void
plug_set_timeout (struct arglist * desc, int timeout)
{
    arg_add_value(desc, "TIMEOUT", ARG_INT, sizeof(gpointer), GSIZE_TO_POINTER(timeout));
}

int
plug_get_timeout (struct arglist * desc)
{
  return GPOINTER_TO_SIZE(arg_get_value(desc, "TIMEOUT"));
}


void
plug_set_launch (struct arglist * desc, int launch)
{
  if(arg_set_value(desc, "ENABLED", sizeof(gpointer), GSIZE_TO_POINTER(launch)))
  {
   arg_add_value(desc, "ENABLED", ARG_INT, sizeof(gpointer), GSIZE_TO_POINTER(launch));
  }
}


int
plug_get_launch (struct arglist * desc)
{
  return(GPOINTER_TO_SIZE(arg_get_value(desc, "ENABLED")));
}


void
plug_set_name (struct arglist * desc, const char * name)
{
 if (! name) return;

 arg_add_value(desc, "NAME", ARG_STRING,
               strlen(name), estrdup(name));
}

char *
plug_get_name (struct arglist * desc)
{
  return arg_get_value(desc, "NAME");
}


void
plug_set_summary (struct arglist * desc, const char* summary)
{
 if (! summary) return;

 arg_add_value(desc, "SUMMARY", ARG_STRING,
               strlen(summary), estrdup(summary));
}

char *
plug_get_summary (struct arglist * desc)
{
 return arg_get_value(desc, "SUMMARY");
}


void
plug_set_description (struct arglist * desc, const char * description)
{
 if (! description) return;

 arg_add_value(desc, "DESCRIPTION", ARG_STRING,
               strlen(description), estrdup(description));
}

char *
plug_get_description (struct arglist * desc)
{
 return arg_get_value(desc, "DESCRIPTION");
}

void
plug_set_copyright (struct arglist * desc, const char* copyright)
{
 if (! copyright) return;

 arg_add_value(desc, "COPYRIGHT", ARG_STRING,
               strlen(copyright), estrdup(copyright));
}

char *
plug_get_copyright (struct arglist * desc)
{
 return arg_get_value(desc, "COPYRIGHT");
}


void
plug_set_category (struct arglist * desc, int category)
{
  arg_add_value(desc, "CATEGORY", ARG_INT, sizeof(gpointer), GSIZE_TO_POINTER(category));
}

int
plug_get_category (struct arglist * desc)
{
 return GPOINTER_TO_SIZE(arg_get_value(desc, "CATEGORY"));
}


void
plug_add_host (struct arglist * desc, struct arglist * hostname)
{
  struct arglist * h;

  h = arg_get_value (desc, "HOSTNAME");
  if(!h)
    arg_add_value (desc, "HOSTNAME", ARG_ARGLIST, sizeof(hostname), hostname);
  else
    arg_set_value (desc, "HOSTNAME", sizeof(hostname), hostname);
}


void
host_add_port_proto (struct arglist * args, int portnum, int state, char * proto)
{
 char port_s[255];
 snprintf (port_s, sizeof(port_s), "Ports/%s/%d", proto, portnum); /* RATS: ignore */
 plug_set_key (args, port_s, ARG_INT, (void*)1);
}


void
host_add_port (struct arglist * hostdata, int portnum, int state)
{
 host_add_port_proto(hostdata, portnum, state, "tcp");
}

void
host_add_port_udp (struct arglist * hostdata, int portnum, int state)
{
 host_add_port_proto(hostdata, portnum, state, "udp");
}

int
port_in_ports (u_short port, u_short * ports, int s, int e)
{
 int mid = (s+e)/2;
 if(s==e)return(port == ports[e]);
 if(port > ports[mid])return(port_in_ports(port, ports, mid+1, e));
 else return(port_in_ports(port, ports, s, mid));
}

/**
 * @brief Report state of preferences "unscanned_closed".
 * 
 * @return 0 if pref is "yes", 1 otherwise.
 */
static int
unscanned_ports_as_closed (struct arglist * prefs)
{
 char * unscanned;
 unscanned = arg_get_value(prefs, "unscanned_closed");
 if (unscanned && !strcmp(unscanned, "yes"))
  return 0;
 else
  return 1;
}


/**
 * @param proto Protocol (udp/tcp). If NULL, "tcp" will be used.
 */
int
kb_get_port_state_proto (struct kb_item ** kb, struct arglist * prefs,
                             int portnum, char * proto)
{
 char port_s[255];
 unsigned short * range;
 char * prange = (char*)arg_get_value(prefs, "port_range");
 int num;

 if (!proto)
  proto = "tcp";

 /* Check that we actually scanned the port */
 if (!strcmp(proto, "tcp") && kb_item_get_int(kb, "Host/scanned") <= 0)
    return unscanned_ports_as_closed(prefs);
 else if(!strcmp(proto, "udp") && kb_item_get_int(kb, "Host/udp_scanned") <= 0)
    return 1;

 range = (u_short*)getpts(prange, &num);

 if (range == NULL)
    return(1);

 if (!port_in_ports(portnum, range, 0, num))
    return unscanned_ports_as_closed(prefs);

 /* Ok, we scanned it. What is its state ? */
 snprintf(port_s, sizeof(port_s), "Ports/%s/%d", proto, portnum); /* RATS: ignore */
 if(kb_item_get_int(kb, port_s) > 0 )
    return 1;
  else
   return 0;
}

int
host_get_port_state_proto (struct arglist * plugdata, int portnum, char * proto)
{
 struct kb_item ** kb = plug_get_kb(plugdata);
 struct arglist * prefs = arg_get_value(plugdata, "preferences");

 return kb_get_port_state_proto(kb, prefs, portnum, proto);
}

int
host_get_port_state (struct arglist * plugdata, int portnum)
{
 return(host_get_port_state_proto(plugdata, portnum, "tcp"));
}

int
host_get_port_state_udp (struct arglist * plugdata, int portnum)
{
 return(host_get_port_state_proto(plugdata, portnum, "udp"));
}


const char *
plug_get_hostname (struct arglist * desc)
{
 struct arglist * hinfos = arg_get_value(desc, "HOSTNAME");
 if(hinfos)return((char*)arg_get_value(hinfos, "NAME"));
 else return(NULL);
}

const char *
plug_get_host_fqdn (struct arglist * desc)
{
 struct arglist * hinfos = arg_get_value(desc, "HOSTNAME");
 if(hinfos)return((char*)arg_get_value(hinfos, "FQDN"));
 else return(NULL);
}


struct in6_addr *
plug_get_host_ip (struct arglist * desc)
{
 struct arglist * hinfos = arg_get_value(desc, "HOSTNAME");
 if (hinfos)
   return ((struct in6_addr*) arg_get_value(hinfos, "IP"));
 else
   return NULL;
}


/**
 * @brief Sets a Success kb- entry for the plugin described with parameter desc.
 * 
 * @param desc Plugin-arglist.
 */
static void
mark_successful_plugin (struct arglist * desc)
{
 char * oid = plug_get_oid(desc);
 char data[512];

 bzero(data, sizeof(data));
 snprintf(data, sizeof(data), "Success/%s", oid); /* RATS: ignore */
 plug_set_key(desc, data, ARG_INT,(void*)1);
}

static void
mark_post (struct arglist * desc, const char* action, char* content)
{
 char entry_name[255];

 if(strlen(action) > (sizeof(entry_name) - 20))
  return;

 snprintf (entry_name, sizeof(entry_name), "SentData/%s/%s", plug_get_oid(desc), action); /* RATS: ignore */
 plug_set_key (desc, entry_name, ARG_STRING, content);
}


/**
 * @brief Post a security message (e.g. LOG, NOTE, WARNING ...).
 * 
 * @param port  Port number related to the issue.
 * @param proto Protocol related to the issue.
 */
void
proto_post_wrapped (struct arglist * desc, int port, const char* proto,
                    const char* action, const char* what)
{
 char * buffer;
 int soc;
 char * naction;
 int len;
 char * cve;
 char * bid;
 char * xref;

 if (action == NULL)
   action = plug_get_description (desc);

 cve  = plug_get_cve_id (desc);
 bid  = plug_get_bugtraq_id (desc);
 xref = plug_get_xref (desc);

 if (action == NULL)
  return;

 len = strlen(action) + 1;
 if (cve != NULL)
  len += strlen(cve) + 20;

 if (bid != NULL)
  len += strlen(bid) + 20;

 if (xref != NULL)
  len += strlen(xref) + 20;

 naction = emalloc (len+1);
 strncpy (naction, action, strlen(action));
 strcat (naction, "\n");
 if (cve != NULL && cve[0] != '\0')
  {
    strcat (naction, "CVE : "); /* RATS: ignore */
    strcat (naction, cve); /* RATS: ignore */
    strcat (naction, "\n");
  }

 if (bid != NULL && bid[0] != '\0')
  {
    strcat (naction, "BID : "); /* RATS: ignore */
    strcat (naction, bid); /* RATS: ignore */
    strcat (naction, "\n");
  }

 if (xref != NULL && xref[0] != '\0')
  {
    strcat(naction, "Other references : "); /* RATS: ignore */
    strcat(naction, xref); /* RATS: ignore */
    strcat(naction, "\n");
  }

  {
   char * old = naction;
   len -= strlen (naction);
   naction = addslashes (naction);
   len += strlen (naction);
   efree (&old);
  }

 buffer = emalloc (1024 + len);
 char idbuffer[105];
 const char *svc_name = nessus_get_svc_name (port, proto);
 if (plug_get_oid(desc) == NULL)
  {
   *idbuffer = '\0';
  }
 else
   {
     char * oid = plug_get_oid(desc);
     snprintf(idbuffer, sizeof(idbuffer), "<|> %s ", oid); /* RATS: ignore */
   }
 if(port>0)
    {
      snprintf (buffer, 1024 + len,
                "SERVER <|> %s <|> %s <|> %s (%d/%s) <|> %s %s<|> SERVER\n",
                what,
                plug_get_hostname(desc),
                svc_name,
                port, proto, naction, idbuffer);
   }
  else
     snprintf (buffer, 1024 + len,
               "SERVER <|> %s <|> %s <|> general/%s <|> %s %s<|> SERVER\n",
               what,
               plug_get_hostname(desc),
               proto, naction, idbuffer);

  mark_post (desc, what, action);
  soc = GPOINTER_TO_SIZE (arg_get_value(desc, "SOCKET"));
  internal_send (soc, buffer, INTERNAL_COMM_MSG_TYPE_DATA);

  /* Mark in the KB that the plugin was sucessful */
  mark_successful_plugin (desc);
  efree (&buffer);
  efree (&naction);
}

void
proto_post_hole (struct arglist * desc, int port, const char * proto,
                 const char * action)
{
  proto_post_wrapped (desc, port, proto, action, "HOLE");
}


void
post_hole (struct arglist * desc, int port, const char * action)
{
  proto_post_hole(desc, port, "tcp", action);
}


void
post_hole_udp (struct arglist * desc, int port, const char * action)
{
 proto_post_hole(desc, port, "udp", action);
}


void
post_info (struct arglist * desc, int port, const char* action)
{
  proto_post_info(desc, port, "tcp", action);
}


void
post_info_udp (struct arglist * desc, int port, const char * action)
{
 proto_post_info(desc, port, "udp", action);
}


void
proto_post_info (struct arglist * desc, int port, const char * proto,
                 const char * action)
{
  proto_post_wrapped(desc, port, proto, action, "INFO");
}

void
post_note (struct arglist * desc, int port, const char* action)
{
  proto_post_wrapped(desc, port, "tcp", action, "NOTE");
}


void
post_note_udp (struct arglist * desc, int port, const char * action)
{
  proto_post_wrapped(desc, port, "udp", action, "NOTE");
}

void proto_post_note (struct arglist * desc, int port, const char* proto,
                      const char* action)
{
  proto_post_wrapped(desc, port, proto, action, "NOTE");
}

/**
 * @brief Post a log message
 */
void
proto_post_log (struct arglist * desc, int port, const char* proto,
                const char* action)
{
  proto_post_wrapped(desc, port, proto, action, "LOG");
}

/**
 * @brief Post a log message about a tcp port.
 */
void
post_log (struct arglist * desc, int port, const char * action)
{
  proto_post_log(desc, port, "tcp", action);
}

/**
 * @brief Post a log message about a udp port.
 */
void
post_log_udp (struct arglist * desc, int port, const char * action)
{
  proto_post_log(desc, port, "udp", action);
}

void
proto_post_debug (struct arglist * desc, int port, const char* proto,
                  const char* action)
{
  proto_post_wrapped(desc, port, proto, action, "DEBUG");
}


void
post_debug (struct arglist * desc, int port, const char* action)
{
  proto_post_debug(desc, port, "tcp", action);
}

/**
 * @brief Post a debug message about a udp port.
 */
void
post_debug_udp (struct arglist * desc, int port, const char* action)
{
  proto_post_debug(desc, port, "udp", action);
}


char *
get_preference (struct arglist *desc, const char * name)
{
 struct arglist * prefs;
 prefs = arg_get_value(desc, "preferences");
 if(!prefs)return(NULL);
 return((char *)arg_get_value(prefs, name));
}

void
add_plugin_preference (struct arglist *desc, const char* name, const char* type,
                       const char* defaul)
{
 struct arglist * prefs = arg_get_value(desc, "PLUGIN_PREFS");
 char pref[1024];

 if(prefs == NULL)
  {
   prefs = emalloc(sizeof(struct arglist));
   arg_add_value(desc, "PLUGIN_PREFS", ARG_ARGLIST, -1, prefs);
  }

 snprintf(pref, sizeof(pref), "%s/%s", type, name); /* RATS: ignore */
 arg_add_value(prefs, pref, ARG_STRING, strlen(defaul), estrdup(defaul));
}


char *
get_plugin_preference (struct arglist * desc, const char * name)
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

const char *
get_plugin_preference_fname (struct arglist * desc, const char * filename)
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


void *
plug_get_fresh_key (struct arglist* args, char* name, int* type)
{
 struct arglist * globals = arg_get_value(args, "globals");
 int soc = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
 int e;
 char * buf = NULL;
 int bufsz = 0;
 int msg;

 if ( name == NULL || type == NULL ) return NULL;
 *type = -1;

 e = internal_send(soc, name, INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_GET);
 if(e < 0){
        fprintf(stderr, "[%d] plug_get_fresh_key:internal_send(%d, %s): %s\n",
                getpid(), soc, name, strerror(errno));
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
  return GSIZE_TO_POINTER(ret);
 }
err:
 if ( buf != NULL )efree(&buf);
 return NULL;
}

static void
plug_set_replace_key (struct arglist * args, char * name, int type,
                      void * value, int replace)
{
 struct kb_item ** kb = plug_get_kb(args);
 struct arglist * globals = arg_get_value(args, "globals");
 int soc = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
 char * str = NULL;
 int msg;

#ifdef DEBUG
 printf("set key %s -> %d\n", name, value);
#endif

 if( name == NULL || value == NULL )return;

 switch (type)
  {
    case ARG_STRING :
      kb_item_add_str (kb, name, value);
      value = addslashes(value);
      str = emalloc(strlen(name)+strlen(value)+10);
      // RATS: ignore
      snprintf(str, strlen(name)+strlen(value)+10, "%d %s=%s;\n", ARG_STRING, name,
              (char *)value);
      efree(&value);
      break;
    case ARG_INT :
      kb_item_add_int(kb, name, GPOINTER_TO_SIZE(value));
      str = emalloc(strlen(name)+20);
      // RATS: ignore
      snprintf(str, strlen(name)+20, "%d %s=%d;\n", ARG_INT, name, (int)GPOINTER_TO_SIZE(value));
      break;
  }

 if (str)
    {
      int e;
      if (replace != 0)
        msg = INTERNAL_COMM_MSG_TYPE_KB|INTERNAL_COMM_KB_REPLACE;
      else
        msg = INTERNAL_COMM_MSG_TYPE_KB;

      e = internal_send (soc, str, msg);
      if (e < 0)
        fprintf(stderr, "[%d] plug_set_key:internal_send(%d)['%s']: %s\n",getpid(), soc,str, strerror(errno));
      efree(&str);
    }
}


void
plug_set_key (struct arglist* args, char * name, int type, void* value)
{
 plug_set_replace_key (args, name, type, value, 0);
}


void
plug_replace_key (struct arglist * args, char* name, int type, void* value)
{
 plug_set_replace_key(args, name, type, value, 1);
}

void
scanner_add_port (struct arglist * args, int port, char* proto)
{
 char * buf;
 const char *svc_name = nessus_get_svc_name(port, proto);
 const char * hn = plug_get_hostname(args);
 int len;
 int soc;
 int do_send = 1;
 static int confirm = -1;

 if(confirm < 0)
 {
  struct arglist * globals = arg_get_value(args, "globals");
  if(globals)confirm = GPOINTER_TO_SIZE(arg_get_value(globals, "confirm"));
 }

 /*
  * Diff scan stuff : if the port was known to be open,
  * there is no need to report it again.
  */
 if(arg_get_value(args, "DIFF_SCAN"))
 {
   char port_s[255];
   snprintf(port_s, sizeof(port_s), "Ports/%s/%d", proto, port); /* RATS: ignore */
   if(kb_item_get_int(plug_get_kb(args), port_s) > 0) do_send = 0;
 }


 host_add_port_proto(args, port, 1, proto);

 len = 255 + (hn ? strlen(hn):0) + strlen(svc_name);
 buf = emalloc(len);
 snprintf(buf, len, "SERVER <|> PORT <|> %s <|> %s (%d/%s) <|> SERVER\n",
          hn,svc_name, port, proto);

 if(do_send)
 {
  soc = GPOINTER_TO_SIZE(arg_get_value(args, "SOCKET"));
  internal_send(soc, buf, INTERNAL_COMM_MSG_TYPE_DATA);
 }
 efree(&buf);
}



struct kb_item **
plug_get_kb (struct arglist * args)
{
 return (struct kb_item**) arg_get_value(args, "key");
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
plug_get_key_sigchld (int sig)
{
 int status;
 wait(&status);
}

static void
sig_n (int signo, void (*fnc)(int) )
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
sig_chld (void(*fcn)(int) )
{
 sig_n(SIGCHLD, fcn);
}
#endif


void *
plug_get_key (struct arglist * args, char * name, int * type)
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
    ret   = GSIZE_TO_POINTER(res->v.v_int);
    }
  else
    {
    if(type != NULL)*type = ARG_STRING;
    ret   = GSIZE_TO_POINTER(res->v.v_str);
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
   old = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
   close(old);
   soc = dup2(sockpair[1], 4);
   close(sockpair[1]);
   arg_set_value(globals, "global_socket", sizeof(gpointer), GSIZE_TO_POINTER(soc));
   arg_set_value(args, "SOCKET", sizeof(gpointer), GSIZE_TO_POINTER(soc));

   if ( globals != NULL ) preferences = arg_get_value(globals, "preferences");
   if ( preferences != NULL )
   {
    char * to = arg_get_value(preferences, "plugins_timeout");
    if ( to != NULL )  tictac = atoi(to);
   }

   srand48(getpid() + getppid() + time(NULL)); /* RATS: ignore */

   sig_term(_exit);
   sig_alarm(_exit);
   alarm(120);


   if ( res->type == KB_TYPE_INT )
   {
    int old_value = res->v.v_int;
     kb_item_rm_all(kb, name); 
     kb_item_add_int(kb, name, old_value);
    if ( type != NULL )*type = ARG_INT;
    return GSIZE_TO_POINTER(old_value);
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
       fprintf(stderr, "nessus-openvas:libopenvas:plugutils.c:plug_get_key(): fork() failed : %s", strerror(errno));
       return NULL;
      }
  else
      {
      int e;
      int status;
      struct arglist * globals;

      globals = arg_get_value(args, "globals");  
      upstream = GPOINTER_TO_SIZE(arg_get_value(globals, "global_socket"));
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

/**
 * Don't always return the first open port, otherwise
 * we might get bitten by OSes doing active SYN flood
 * countermeasures. Also, avoid returning 80 and 21 as
 * open ports, as many transparent proxies are acting for these...
 */
unsigned int
plug_get_host_open_port (struct arglist * desc)
{
 struct kb_item ** kb = plug_get_kb(desc);
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
       return candidates[lrand48() % num_candidates]; /* RATS: ignore */
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



/** @TODO
 * Those brain damaged functions should probably be in another file
 * They are use to remember who speaks SSL or not
 */

void
plug_set_port_transport (struct arglist * args, int port, int tr)
{
  char s[256];

  snprintf(s, sizeof(s), "Transports/TCP/%d", port); /* RATS: ignore */
  plug_set_key(args, s, ARG_INT, GSIZE_TO_POINTER(tr));
}

int
plug_get_port_transport (struct arglist * args, int port)
{
  char s[256];
  int trp;

  snprintf(s, sizeof(s), "Transports/TCP/%d", port); /* RATS: ignore */
  trp = kb_item_get_int(plug_get_kb(args), s);
  if (trp >= 0)
    return trp;
  else
    return NESSUS_ENCAPS_IP; /* Change this to 0 for ultra smart SSL negotiation, at the expense
                                of possibly breaking stuff */
}

const char*
plug_get_port_transport_name (struct arglist * args, int port)
{
  return get_encaps_name(plug_get_port_transport(args, port));
}

static void
plug_set_ssl_item (struct arglist * args, char * item, char * itemfname)
{
 char s[256];
 snprintf(s, sizeof(s), "SSL/%s", item); /* RATS: ignore */
 plug_set_key(args, s, ARG_STRING, itemfname);
}

void
plug_set_ssl_cert (struct arglist * args, char * cert)
{
 plug_set_ssl_item(args, "cert", cert);
}

void
plug_set_ssl_key (struct arglist * args, char * key)
{
 plug_set_ssl_item(args, "key", key);
}

void
plug_set_ssl_pem_password (struct arglist * args, char * key)
{
 plug_set_ssl_item(args, "password", key);
}

void
plug_set_ssl_CA_file (struct arglist * args, char * key)
{
 plug_set_ssl_item(args, "CA", key);
}

char *
find_in_path (char* name, int safe)
{
  char		*buf = getenv("PATH"), *pbuf, *p1, *p2;
  static char	cmd[MAXPATHLEN];
  int		len = strlen(name);

  if (len >= MAXPATHLEN)
    return NULL;

 if (buf == NULL) /* Should we use a standard PATH here? */
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

      snprintf(p2, MAXPATHLEN, "/%s", name); /* RATS: ignore */
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

/**
 * @return -1 in case of error, 0 in case of success.
 */
int shared_socket_register ( struct arglist * args, int fd, char * name )
{
 int soc; 
 int type;
 unsigned int opt_len = sizeof(type);
 int e;
 soc = GPOINTER_TO_SIZE(arg_get_value(args, "SOCKET"));
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

/**
 * @return Socket as from recv_fd or -1 in case of error(s).
 */
int
shared_socket_acquire ( struct arglist * args, char * name )
{
 int soc;
 char * buf = NULL;
 int bufsz = 0;
 int msg;

 soc = GPOINTER_TO_SIZE(arg_get_value(args, "SOCKET"));

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


int
shared_socket_release (struct arglist * args, char * name)
{
 int soc;

 soc = GPOINTER_TO_SIZE(arg_get_value(args, "SOCKET"));
 return internal_send(soc, name, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_RELEASE);
}

int
shared_socket_destroy (struct arglist * args, char * name)
{
 int soc;

 soc = GPOINTER_TO_SIZE(arg_get_value(args, "SOCKET"));
 return internal_send(soc, name, INTERNAL_COMM_MSG_SHARED_SOCKET|INTERNAL_COMM_SHARED_SOCKET_DESTROY);
}
