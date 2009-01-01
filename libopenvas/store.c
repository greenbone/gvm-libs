/* OpenVAS
 * $Id$
 * Description: Undocumented module.
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

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/param.h>

#include <glib.h>

#include "store_internal.h"
#include "share_fd.h"
#include "system.h"
#include "plugutils.h"
#include "plugutils_internal.h"

/*-----------------------------------------------------------------------------*/
static char * arglist2str(struct arglist * arg)
{
 char * ret;
 int sz;
 
 
 
 if(arg == NULL)
  return estrdup("");
 
 if(arg->name == NULL)
  return estrdup("");
  
 sz = (strlen(arg->name) + 1) * 10;
 ret = emalloc(sz);
 strncpy(ret, arg->name, sz - 1);
 arg = arg->next;
 if(arg == NULL)
  return ret;

 while(arg->next != NULL)
 { 
   if(arg->name == NULL)
     return ret;
   if(strlen(arg->name) + 3 + strlen(ret) >= sz )
   {
    sz = strlen(arg->name) + 3 + strlen(ret) * 2;
    ret = erealloc(ret, sz);
   }
   strncat(ret, ", ", sz - 1); /* RATS: ignore */
   strncat(ret, arg->name, sz - 1); /* RATS: ignore */ 
   arg = arg->next;
 }
 return ret;
}


struct arglist * str2arglist(char * str)
{
 struct arglist * ret;
 char * t = strchr(str, ',');


 if(!str || str[0] == '\0')
  {
   return NULL;
  }

 ret = emalloc ( sizeof(struct arglist) );
  
  
 while((t = strchr(str, ',')) != NULL)
 {
  t[0] = 0;
  while(str[0]==' ')str++;
  if(str[0] != '\0')
  {
   arg_add_value(ret, str, ARG_INT, 0, (void*)1);
  }
  str = t+1;
 }
 
 while(str[0]==' ')str++;
 if(str[0] != '\0')
   arg_add_value(ret, str, ARG_INT, 0, (void*)1);
  

  return ret;
}




/*-----------------------------------------------------------------------------*/	
static int safe_copy(char * str, char * dst, int sz, char * path, char * item)
{
 if(str == NULL)	/* empty strings are OK */
  {
  dst[0] = '\0';
  return 0;
  }
  
 if(strlen(str) >= sz)
 {
  fprintf(stderr, "openvas-libraries/libopenvas/store.c: %s has a too long %s (%ld)\n", path, item, (long)strlen(str));
  return -1;
 }
 strcpy(dst, str); /* RATS: ignore */
 return 0;
}
/*-----------------------------------------------------------------------------*/


#define MODE_SYS 0
#define MODE_USR 1

static char sys_store_dir[MAXPATHLEN+1];
static char usr_store_dir[MAXPATHLEN+1];

static int current_mode = -1;



/**
 * Inits the sys_store_dir string to the default value. sys_store_dir holds the 
 * path of the .desc (~server-side plugin cache) directory which is a subfolder
 * of the plugin- directory. If the .desc directory does not exist, it will be 
 * created. Also sets the mode to MODE_SYS.
 * @param dir Path to the (plugin)- directory
 * @return 0 in case of success, -1 if the directory does not exist and could 
 *         not be created.
 */
int store_init_sys(char * dir)
{
 current_mode = MODE_SYS;
 
 snprintf(sys_store_dir, sizeof(sys_store_dir), "%s/.desc", dir); /* RATS: ignore */
 if((mkdir(sys_store_dir, 0755) < 0) && (errno != EEXIST))
 {
  fprintf(stderr, "mkdir(%s) : %s\n", sys_store_dir, strerror(errno));
  return -1;
 }
 
 return 0;
}

/**
 * Inits the sys_store_dir string to the default value. sys_store_dir holds the 
 * path of the .desc (~server-side plugin cache) directory which is a subfolder
 * of the plugin- directory. If the .desc directory does not exist, it will be 
 * created. Also sets the mode to MODE_USR.
 * @param dir Path to the (plugin)- directory
 * @return 0 in case of success, -1 if the directory does not exist and could 
 *         not be created.
 */
int store_init_user(char * dir)
{
 current_mode = MODE_USR;
 snprintf(usr_store_dir, sizeof(usr_store_dir), "%s/.desc", dir); /* RATS: ignore */
 if((mkdir(usr_store_dir, 0755) < 0) && (errno != EEXIST))
 {
  fprintf(stderr, "mkdir(%s) : %s\n", usr_store_dir, strerror(errno));
  return -1;
 } 
 
 return 0;
}



/*--------------------------------------------------------------------------------*/


static int store_get_plugin_f(struct plugin * plugin, struct pprefs * pprefs, char * dir, char * file)
{
 int fd;
 struct plugin * p;
 struct stat st;
 int len;
 char file_name[MAXPATHLEN+1];
 char * str;
 
 bzero(plugin, sizeof(*plugin));
 plugin->id = -1;
 
 if(dir == NULL || dir[0] == '\0' || file == NULL || file[0] == '\0')
 	return -1;
 
 snprintf(file_name, sizeof(file_name), "%s/%s", dir, file); /* RATS: ignore */
 str = strrchr(file_name, '.');
 if(str != NULL)
 {
  str[0] = '\0';
  if(strlen(file_name) + 6 < sizeof(file_name))
  	strncat(file_name, ".desc", MAXPATHLEN); /* RATS: ignore */
 }

 if(file == NULL)
  return -1;
  
 fd = open(file_name, O_RDONLY);
 if(fd < 0)
  return -1;
 
 if(fstat(fd, &st) < 0)
 { 
  perror("fstat ");
  close(fd);
  return -1;
 } 
 
 if(st.st_size == 0)
 {
  close(fd);
  return 0;
 }
 
 len = st.st_size;
 p = (struct plugin*)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
 if(p == MAP_FAILED || p == NULL)
 {
  perror("mmap ");
  close(fd);
  return -1;
 }

 
 bcopy(p, plugin, sizeof(struct plugin));

 
 if(p->has_prefs && pprefs != NULL)
 {
  bcopy((char*)p + sizeof(struct plugin), pprefs, sizeof(struct pprefs) * MAX_PREFS);
 }
 munmap((char*)p, len);
 close(fd);
 return 0;
}


int store_get_plugin(struct plugin * p, char * name)
{
 int e = store_get_plugin_f(p, NULL, usr_store_dir, name);
 if(p->id < 0)
  return store_get_plugin_f(p, NULL, sys_store_dir, name);
 else
  return e;
}

/*--------------------------------------------------------------------------------*/
/* Returns a (plugin) arglist assembled from the description file .desc or NULL
 * if
 * 1) the .desc does not exist
 * 2) Nvt definition file (e.g. xyz.nasl) or nvt signature (xyz.asc) file is
 *       newer than the .desc file
 * 3) the magic number test failed (other file format expected).
 * 4) an error occured.
 * @param dir Path to parent directory of the .desc directory.
 * @param file File name of the plugin (e.g. detect_openvas.nasl ).
 * @param prefs Plugin preference arglist.
 * @return Pointer to plugin as arglist or NULL (see above).
 */
struct arglist * store_load_plugin(char * dir, char * file,  struct arglist * prefs)
{
 char desc_file[MAXPATHLEN+1];
 char plug_file[MAXPATHLEN+1];
 char asc_file[MAXPATHLEN+1];
 char * str;
 char store_dir[MAXPATHLEN+1];
 struct plugin p;
 struct pprefs pp[MAX_PREFS];
 
 struct arglist * ret;
 int i;
 struct stat stat_plug,
        stat_desc,
        stat_asc;
 struct arglist * al;
 
 bzero(pp, sizeof(pp));

 /* Assemble file paths to stat them later */
 snprintf(desc_file, sizeof(desc_file), "%s/.desc/%s", dir, file); /* RATS: ignore */
 str = strrchr(desc_file, '.');
 if( str != NULL )
 {
  str[0] = '\0';
  if(	strlen(desc_file) + 6 < sizeof(desc_file) )
  	strncat(desc_file, ".desc", MAXPATHLEN); /* RATS: ignore */
 }

 snprintf(asc_file, sizeof(asc_file), "%s/%s", dir, file); /* RATS: ignore */

 if( strlen(asc_file) + 5 < sizeof(desc_file) )
 {
   strncat(asc_file, ".asc", MAXPATHLEN); /* RATS: ignore */
 }
 else
 {
   /* Certificate file name is longer than MAXPATHLEN, should not happen */
   return NULL;
 }

 snprintf(plug_file, sizeof(plug_file), "%s/%s", dir, file); /* RATS: ignore */

 /* Plugin and cache file have to exist */
 if (  stat(plug_file, &stat_plug) < 0 || stat(desc_file, &stat_desc) < 0)
   {
   return NULL;
   }

 /* 
  * Look if the plugin (.nasl/.oval etc) or the signature (.asc) is newer than
  * the description (.desc). If that's the case also make sure that
  * the plugin and signatures mtime is not in the future...
  */
 if( stat_plug.st_mtime > stat_desc.st_mtime 
    && stat_asc.st_mtime  > stat_desc.st_mtime )
   {
	return NULL;
   }

 /* 
  * Look if a signature file (.asc) exists. If so and it is newer than
  * the description (.desc) (and the mtime is not in the future), return NULL.
  */ 
 if(    stat(asc_file, &stat_asc) 
     && stat_asc.st_mtime > stat_desc.st_mtime 
     && stat_asc.st_mtime <= time(NULL) )
   {
     return NULL;
   }


 snprintf(store_dir, sizeof(store_dir), "%s/.desc", dir); /* RATS: ignore */
 if(store_get_plugin_f(&p, pp, store_dir, file) < 0)
  return NULL;


 if(p.magic != MAGIC)
 	return NULL;
	
 if(p.oid == NULL) return NULL;

  
 ret = emalloc(sizeof(struct arglist));   
 plug_set_oid(ret, p.oid);
 plug_set_category(ret, p.category);
 plug_set_cachefile(ret, file);
 plug_set_path(ret, p.path);
 plug_set_family(ret, p.family, NULL);
 plug_set_sign_key_ids(ret, p.sign_key_ids);

  al = str2arglist(p.required_ports);
 if ( al != NULL ) arg_add_value(ret, "required_ports", ARG_ARGLIST, -1, al);

 al = str2arglist(p.required_keys);
 if ( al != NULL ) arg_add_value(ret, "required_keys", ARG_ARGLIST, -1, al);

 al = str2arglist(p.required_udp_ports);
 if ( al != NULL ) arg_add_value(ret, "required_udp_ports", ARG_ARGLIST, -1, al)
;

 al = str2arglist(p.excluded_keys);
 if ( al != NULL ) arg_add_value(ret, "excluded_keys", ARG_ARGLIST, -1, al);

 al = str2arglist(p.dependencies);
 if ( al != NULL ) arg_add_value(ret, "DEPENDENCIES", ARG_ARGLIST, -1, al);

 
 if ( p.timeout != 0 ) arg_add_value(ret, "TIMEOUT", ARG_INT, -1, GSIZE_TO_POINTER(p.timeout));

 arg_add_value(ret, "NAME", ARG_STRING, strlen(p.name), estrdup(p.name));


 arg_add_value(ret, "preferences", ARG_ARGLIST, -1, prefs);
 
 if(p.has_prefs)
 {
 for(i=0;pp[i].type[0] != '\0';i++)
  { 
   _add_plugin_preference(prefs, p.name, pp[i].name, pp[i].type, pp[i].dfl);
  }
 }

 return ret;
}

struct arglist * store_plugin(struct arglist * plugin, char * file)
{
 char desc_file[MAXPATHLEN+1];
 char path[MAXPATHLEN+1];
 struct plugin plug;
 struct pprefs pp[MAX_PREFS+1];
 char  * str;
 char * dir;
 struct arglist * arglist, * prefs;
 int e;
 int fd;
 int num_plugin_prefs = 0;
 
 if( current_mode == MODE_SYS )
   dir = sys_store_dir;
  else
   dir = usr_store_dir;
   
  if(strlen(file) + 2 > sizeof(path))
  	return NULL;
 
 strncpy(path, dir, sizeof(path) - 2 - strlen(file));
 str = strrchr(path, '/');
 if(str != NULL)
 {
  str[0] = '\0';
 }
 strcat(path, "/");
 strcat(path, file); /* RATS: ignore */

 
 
 snprintf(desc_file, sizeof(desc_file), "%s/%s", dir, file); /* RATS: ignore */
 str = strrchr(desc_file, '.');
 if( str != NULL )
 {
  str[0] = '\0';
  if(strlen(desc_file) + 6 < sizeof(desc_file) )
  	strncat(desc_file, ".desc", MAXPATHLEN); /* RATS: ignore */
 }

 
 
 bzero(&plug, sizeof(plug));
 bzero(pp, sizeof(pp));
 
 plug.magic = MAGIC;
 plug.id = plug_get_id(plugin);
 e = safe_copy(path, plug.path, sizeof(plug.path), path, "path"); 
 if(e < 0)return NULL;
 
 str = plug_get_oid(plugin);
 e = safe_copy(str, plug.oid, sizeof(plug.oid), path, "oid");
 if(e < 0)return NULL;

 
 plug.timeout = plug_get_timeout(plugin);
 plug.category = plug_get_category(plugin);
 
 str = plug_get_name(plugin);
 e = safe_copy(str, plug.name, sizeof(plug.name), path, "name");
 if(e < 0)return NULL;
 
 
 str = _plug_get_version(plugin);
 e = safe_copy(str, plug.version, sizeof(plug.version), path, "version");
 if(e < 0)return NULL;
 
 
 str = _plug_get_summary(plugin);
 e = safe_copy(str, plug.summary, sizeof(plug.summary), path, "summary");
 if(e < 0)return NULL;
 
 str = _plug_get_description(plugin);
 e = safe_copy(str, plug.description, sizeof(plug.description), path, "description");
 if(e < 0)return NULL;
 
 str = _plug_get_copyright(plugin);
 e = safe_copy(str, plug.copyright, sizeof(plug.copyright), path, "copyright");
 if(e < 0)return NULL;
 
 str = _plug_get_family(plugin);
 e = safe_copy(str, plug.family, sizeof(plug.family), path, "family");
 if(e < 0)return NULL;
 
 str = _plug_get_cve_id(plugin);

 e = safe_copy(str, plug.cve_id, sizeof(plug.cve_id), path, "cve_id");
 if(e < 0)return NULL;
 
 str = _plug_get_bugtraq_id(plugin);
 e = safe_copy(str, plug.bid, sizeof(plug.bid), path, "bugtraq id");
 if(e < 0)return NULL;
 
 str = _plug_get_xref(plugin);
 e = safe_copy(str, plug.xref, sizeof(plug.xref), path, "xref id");
 if(e < 0)return NULL;

 str = _plug_get_tag(plugin);
 e = safe_copy(str, plug.tag, sizeof(plug.tag), path, "tag");
 if(e < 0)return NULL;
 
 arglist = plug_get_deps(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.dependencies, sizeof(plug.dependencies), path, "dependencies");
 efree(&str);
 if(e < 0)return NULL;
 
 arglist = plug_get_required_keys(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.required_keys, sizeof(plug.required_keys), path, "required keys");
 efree(&str);
 if(e < 0)return NULL;
 
 arglist = plug_get_excluded_keys(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.excluded_keys, sizeof(plug.excluded_keys), path, "excluded_keys");
 efree(&str);
 if(e < 0)return NULL;
 
 arglist = plug_get_required_ports(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.required_ports, sizeof(plug.required_ports), path, "required ports");
 efree(&str);
 if(e < 0)return NULL;
 
 arglist = plug_get_required_udp_ports(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.required_udp_ports, sizeof(plug.required_udp_ports), path, "required udp ports");
 efree(&str);
 if(e < 0)return NULL;

 str = plug_get_sign_key_ids(plugin);
 e = safe_copy(str, plug.sign_key_ids, sizeof(plug.sign_key_ids), path, "key ids of signatures");
 //efree(&str);
 if(e < 0)return NULL;
 
 
 prefs = arg_get_value(plugin, "preferences");
 
 arglist = arg_get_value(plugin, "PLUGIN_PREFS");
 if( arglist != NULL )
 {
  char * p_name = plug_get_name(plugin);
  
  while(arglist->next != NULL)
  {
   char * name = arglist->name;
   char * dfl = arglist->value;
   char * type, * str;
   
   type = arglist->name;
   str = strchr(type, '/');
   str[0] = '\0';
   name = str + 1;
   e = safe_copy(type, pp[num_plugin_prefs].type, sizeof(pp[num_plugin_prefs].type), path, "preference-type");
   if(e < 0)return NULL;
   e = safe_copy(name, pp[num_plugin_prefs].name, sizeof(pp[num_plugin_prefs].name), path, "preference-name");
   if(e < 0)return NULL;
   e = safe_copy(dfl, pp[num_plugin_prefs].dfl, sizeof(pp[num_plugin_prefs].dfl), path, "preference-default");
   if(e < 0)return NULL;
   num_plugin_prefs ++;
  
   
   if(num_plugin_prefs >= MAX_PREFS)
   {
    fprintf(stderr, "%s: too many preferences\n", path);
    return NULL;
   }
   _add_plugin_preference(prefs, p_name, name, type, dfl);
   str[0] = '/';
   arglist = arglist->next;
  }
 }
 
 if(num_plugin_prefs > 0)
  plug.has_prefs = 1;
 
 fd = open(desc_file, O_RDWR|O_CREAT|O_TRUNC, 0644);
 if(fd < 0)
 { 
  return NULL;
 }
 
 if(write(fd, &plug, sizeof(plug)) < 0)
 {
  perror("write ");
 }
 
 if(num_plugin_prefs > 0)
 {
  write(fd, pp, sizeof(pp));
 }
 close(fd); 
 
 

 arg_set_value(plugin, "preferences", -1, NULL);
 arg_free_all(plugin);
 return NULL;
}


/*---------------------------------------------------------------------*/


char * store_fetch_path(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.path;
}

char * store_fetch_version(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.version;
}

char * store_fetch_summary(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.summary;
}

char * store_fetch_description(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.description;
}

int store_fetch_category(struct arglist * desc)
{
 return plug_get_category(desc);
}

char * store_fetch_copyright(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.copyright;
}

char * store_fetch_family(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.family;
}

char * store_fetch_oid(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.oid;
}

char * store_fetch_cve_id(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.cve_id;
}

char * store_fetch_bugtraq_id(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.bid;
}


char * store_fetch_xref(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.xref;
}

char * store_fetch_tag(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 
 store_get_plugin(&p, fname);
 return p.tag;
}

struct arglist * store_fetch_required_keys(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 struct arglist * ret;
 
 store_get_plugin(&p, fname);
 ret = str2arglist(p.required_keys);
 return ret; 
}

struct arglist * store_fetch_excluded_keys(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 struct arglist * ret;
 
 store_get_plugin(&p, fname);
 ret = str2arglist(p.excluded_keys);
 return ret; 
}

struct arglist * store_fetch_required_ports(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 struct arglist * ret;
 
 store_get_plugin(&p, fname);
 ret = str2arglist(p.required_ports);
 return ret; 
}

struct arglist * store_fetch_required_udp_ports(struct arglist * desc)
{
 char * fname = plug_get_cachefile(desc);
 static struct plugin p;
 struct arglist * ret;
 
 store_get_plugin(&p, fname);
 ret = str2arglist(p.required_udp_ports);
 return ret; 
}


 
/*---------------------------------------------------------------------*/

#if 0
void store_dump_plugin(int id)
{
 struct plugin plugin;
 store_get_plugin(&plugin, id);
 
 printf("PLUGIN ID# %d\n", plugin.id);
 printf("in %s\n", plugin.path);
 printf("\n\n");
 printf("Name: %s\n", plugin.name);
 printf("timeout : %d\n", plugin.timeout);
 printf("category: %d\n",  plugin.category);
 printf("version : %s\n",  plugin.version);
 printf("summary : %s\n",  plugin.summary);
 printf("description: %s\n",  plugin.description);
 printf("copyright: %s\n",  plugin.copyright);
 printf("family %s\n",  plugin.family);
 printf("cve_id : %s\n",  plugin.cve_id);
 printf("bid : %s\n",  plugin.bid);
 printf("xrefs : %s\n",  plugin.xrefs);
 printf("tags : %s\n",  plugin.tags);
 printf("dependencies: %s\n", plugin.dependencies);
 printf("required_keys : %s\n", plugin.required_keys);
 printf("excluded_key : %s\n", plugin.excluded_keys);
 printf("required_ports: %s\n", plugin.required_ports);
 printf("required_udp_ports: %s\n", plugin.required_udp_ports);
}
#endif
