/* OpenVAS
 * $Id$
 * Description: Functions related to plugin cache and.
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

/** @file
 * OpenVAS-Server employs a plugin cache to avoid parsing all known nvts at
 * start-up.
 *
 * The cache consists of a .desc file for each script (e.g. cache file of
 * nvts/xyz.nasl is nvts/xyz.nas.desc), which contains a memory dump of the
 * corresponding plugin struct.
 *
 * The cache is used as followed:
 *
 * 1. Init the store with store_init.
 *
 * 2. Add nvts by calling store_plugin or
 *
 * 3. Give the store a file path (store_load_plugin)
 * and receive the plugin as arglist. Under nice conditions the information
 * contained in the cache file can be used. Under not so nice conditions, the
 * store returns NULL (cache is either outdated, contains error or an error
 * occurred).
 *
 * The store is updated at each openvasd start up. There the plugin loader
 * iterates over plugin files and tries to retrieve the cached version.
 * If there is no cached version (or @ref store_load_plugin returns Null for
 * another reason, e.g.because  the script file seems to have been modified in
 * between) the plugin is added to the store (@ref store_plugin).
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
static char *
arglist2str(struct arglist * arg)
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


/**
 * @brief Copies content of one string into the other.
 *
 * Does not check nul-termination.
 * If it fails, an error message containing the name of the NVT and the
 * description of the failed property will be printed to stderr.
 *
 * @param str Source string, might be NULL.
 * @param dst Destination string.
 * @param sz max number of bytes to copy into dst.
 * @param filename Filename of the NVT, used in the error message.
 * @param item Description of the property to be copied, used in the error
 * message.
 *
 * @return 0 on success, -1 otherwise.
 */
static int
safe_copy (char * str, char * dst, int sz, char * filename, char * item)
{
 if (str == NULL) /* empty strings are OK */
  {
    dst[0] = '\0';
    return 0;
  }

 if (strlen(str) >= sz)
  {
    fprintf(stderr, "\r%s: The length of the value for the property \"%s\" exceeds the allowed maximum length (is %ld characters, maximum length is %d).\n", filename, item, (long) strlen (str), sz);
    return -1;
  }

 strcpy (dst, str); /* RATS: ignore */
 return 0;
}

/**
 * @brief Holds the directory name for the cache.
 * 
 * If run with older
 * installations of OpenVAS (<=2.0.0), then it is initialized with
 * the NVT directory (server preference "plugins_folder")
 * and appends "/.desc/". For newer versions it is the directory
 * specified as server preference "cache_folder".
 */
static char store_dir[MAXPATHLEN+1] = "";

/**
 * @brief Sets the @ref store_dir to the given path.
 *
 * @param dir Path to the cache-directory. It must exist.
 *
 * @return    0  in case of success (@ref store_dir is set now)
 *            -1 if the given path exeeds the buffer size
 *            -2 if the directory does not exist
 *            -3 if the given path was NULL
 *            In any other case than 0 @ref store_dir is
 *            not set and a error is printed to stderr
 */
int
store_init (const char * dir)
{
  struct stat st;
  int i = 0;

  if (dir == NULL) {
    fprintf(stderr, "store_init(): called with NULL\n");
    return -3;
  }

  for (;i < sizeof(store_dir) && dir[i];i ++)
    ;
  if (i == sizeof(store_dir)) {
    fprintf(stderr,
            "store_init(): path too long with more than %d characters\n", i);
    return -1;
  }

  if (stat(dir, &st) < 0) { // check for existance
    fprintf(stderr, "stat(%s): %s\n", dir, strerror(errno));
    return -2;
  }

  strncpy (store_dir, dir, sizeof(store_dir));

  return 0;
}

/**
 * @brief Deprecated function to set the directory where the plugin cache files are placed.
 *
 * Don't use this method anymore. It is here only for legacy to be compatible with
 * openvas-server <= 2.0.0.
 * The new method to use is @ref store_init .
 *
 * @return Always 0.
 */
int
store_init_sys (char * dir)
{
 snprintf(store_dir, sizeof(store_dir), "%s/.desc", dir); /* RATS: ignore */
 if((mkdir(store_dir, 0755) < 0) && (errno != EEXIST))
 {
  fprintf(stderr, "mkdir(%s) : %s\n", store_dir, strerror(errno));
  return -1;
 }

 return 0;
}

/**
 * @brief Deprecated function to set the directory where the plugin cache files are placed.
 *
 * Don't use this method anymore. It is here only for legacy to be compatible with
 * openvas-server <= 2.0.0.
 * The new method to use is @ref store_init .
 */
int store_init_user(char * dir)
{
  return store_init_sys(dir);
}

/**
 * @brief Internal function to load plugin description from cache file
 *
 * @param plugin    This structure is filled with the loaded plugin data
 *
 * @param pprefs    This structure is filled with the loaded
 *                  plugin preferences.
 *
 * @param prefs     Plugin preference arglist.
 *
 * @param desc_file The full path to the cache file.

 * @return -1 upon failure, 0 for success.
 */
static int
store_get_plugin_f (struct plugin * plugin, struct pprefs * pprefs,
                    gchar * desc_file)
{
 int fd;
 struct plugin * p;
 struct stat st;
 int len;

 bzero(plugin, sizeof(*plugin));
 plugin->id = -1;

  if(desc_file == NULL || desc_file[0] == '\0')
    return -1;

 fd = open(desc_file, O_RDONLY);
 if(fd < 0)
  return -1;

 if(fstat(fd, &st) < 0)
 {
  perror("fstat ");
  close (fd);
  return -1;
 }
 
 if(st.st_size == 0)
 {
  close (fd);
  return 0;
 }
 
 len = st.st_size;
 p = (struct plugin*)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
 if(p == MAP_FAILED || p == NULL)
 {
  perror("mmap ");
  close (fd);
  return -1;
 }

 bcopy(p, plugin, sizeof(struct plugin));

 if(p->has_prefs && pprefs != NULL)
 {
  bcopy((char*)p + sizeof(struct plugin), pprefs, sizeof(struct pprefs) * MAX_PREFS);
 }
 munmap((char*)p, len);
 close (fd);
 return 0;
}


int store_get_plugin(struct plugin * p, char * desc_file)
{
  return store_get_plugin_f(p, NULL, desc_file);
}


/**
 * @brief Returns a (plugin) arglist assembled from the cached description file
 *
 * @param dir Path to location of plugin file
 *
 * @param file Filename of the plugin (e.g. "detect_openvas.nasl"
 *             or "subdir1/subdir2/scriptname.nasl" ).
 *
 * @param prefs Plugin preference arglist.
 *
 * NULL is returned in either of these cases:
 * 1) The .NVT definition or .desc file does not exist.
 * 2) NVT definition file (e.g. xyz.nasl) or nvt signature (xyz.asc) file is
 *    newer than the .desc file.
 * 3) The NVT definition files (e.g. xyz.nasl) or nvt signature (xyz.asc) files
 *    timestamp is in the future.
 * 4) The magic number test failed (other file format expected).
 * 5) An internal error occured.
 *
 * Point 4) is necessary because the cache will not create .desc files with
 * timestamps in the future. Thus, when creating a new cache file for the given
 * NVT, it would not be able to become loaded from the cache (point 2)).
 *
 * @return Pointer to plugin as arglist or NULL.
 */
struct arglist *
store_load_plugin (const char * dir, const char * file, struct arglist * prefs)
{
  gchar * plug_file = g_build_filename (dir, file, NULL);
  gchar * asc_file  = g_strconcat (plug_file, ".asc", NULL);
  gchar * dummy     = g_build_filename (store_dir, file, NULL);
  gchar * desc_file = g_strconcat (dummy, ".desc", NULL);

  struct plugin p;
  struct pprefs pp[MAX_PREFS];

  struct arglist * ret;
  struct arglist * al;

  struct stat stat_plug;
  struct stat stat_desc;
  struct stat stat_asc;

  int i;

  g_free (dummy);

  if (desc_file == NULL || asc_file == NULL || plug_file == NULL)
    {
      g_free (desc_file);
      g_free (asc_file);
      g_free (plug_file);
      return NULL; // g_build_filename failed
    }

  bzero (pp, sizeof(pp));

  /* Plugin and cache file have to exist */
  if (stat(plug_file, &stat_plug) < 0 || stat(desc_file, &stat_desc) < 0)
    {
      g_free (desc_file);
      g_free (asc_file);
      g_free (plug_file);
      return NULL;
    }

   /* Look if the plugin (.nasl/.oval etc) is newer than the description
    * (.desc). If that's the case also make sure that the plugins mtime is not
    * in the future...  */
   if (   stat_plug.st_mtime > stat_desc.st_mtime
       && stat_asc.st_mtime  <= time (NULL))
    {
      g_free (desc_file);
      g_free (asc_file);
      g_free (plug_file);
      return NULL;
    }

  /* Look if a signature file (.asc) exists. If so and it is newer than
   * the description (.desc) (and the mtime is not in the future), return NULL.  */
  if (   stat (asc_file, &stat_asc) == 0
      && stat_asc.st_mtime > stat_desc.st_mtime
      && stat_asc.st_mtime <= time (NULL) )
    {
      g_free (desc_file);
      g_free (asc_file);
      g_free (plug_file);
      return NULL;
    }

  if ((store_get_plugin_f(&p, pp, desc_file) < 0) ||
      (p.magic != MAGIC) ||
      (p.oid == NULL))
    {
      g_free (desc_file);
      g_free (asc_file);
      g_free (plug_file);
      return NULL;
    }

  ret = emalloc (sizeof(struct arglist));
  plug_set_oid (ret, p.oid);
  plug_set_category (ret, p.category);
  plug_set_cachefile (ret, desc_file);
  plug_set_path (ret, p.path);
  plug_set_family (ret, p.family, NULL);
  plug_set_sign_key_ids (ret, p.sign_key_ids);

  al = str2arglist (p.required_ports);
  if (al != NULL) arg_add_value (ret, "required_ports", ARG_ARGLIST, -1, al);

  al = str2arglist (p.required_keys);
  if (al != NULL) arg_add_value (ret, "required_keys", ARG_ARGLIST, -1, al);

  al = str2arglist (p.required_udp_ports);
  if (al != NULL) arg_add_value (ret, "required_udp_ports", ARG_ARGLIST, -1, al);

  al = str2arglist (p.excluded_keys);
  if (al != NULL) arg_add_value (ret, "excluded_keys", ARG_ARGLIST, -1, al);

  al = str2arglist (p.dependencies);
  if (al != NULL) arg_add_value (ret, "DEPENDENCIES", ARG_ARGLIST, -1, al);

  if (p.timeout != 0) arg_add_value (ret, "TIMEOUT", ARG_INT, -1, GSIZE_TO_POINTER(p.timeout));

  arg_add_value (ret, "NAME", ARG_STRING, strlen(p.name), estrdup(p.name));

  arg_add_value (ret, "preferences", ARG_ARGLIST, -1, prefs);

  if (p.has_prefs)
    {
      for (i=0; pp[i].type[0] != '\0'; i++)
        {
         _add_plugin_preference (prefs, p.name, pp[i].name, pp[i].type, pp[i].dfl);
        }
    }

  g_free (desc_file);
  g_free (asc_file);
  g_free (plug_file);

  return ret;
}

/**
 * @brief Creates an entry in the store for data of "plugin" into cache file
 * @brief "file" which is placed in the cache directory.
 *
 * @param plugin    Data structure that contains a plugin description
 * @param file      Name of corresponding plugin file (e.g. "x.nasl", "x.nes"
 *                  or "x.oval". It can also be something like
 *                  "subdir1/subdir2/scriptname.nasl").
 */
void
store_plugin (struct arglist * plugin, char * file)
{
  gchar * dummy = g_build_filename (store_dir, file, NULL);
  gchar * desc_file = g_strconcat (dummy, ".desc", NULL);
  // assume there is a ".desc" at the end in the store_dir path
  gchar * path = g_strdup (file);
 struct plugin plug;
 struct pprefs pp[MAX_PREFS+1];
 char  * str;
 struct arglist * arglist, * prefs;
 int e;
 int fd;
 int num_plugin_prefs = 0;

  g_free(dummy);

  if (desc_file == NULL || path == NULL) return; // g_build_filename failed

 bzero(&plug, sizeof(plug));
 bzero(pp, sizeof(pp));
 
 plug.magic = MAGIC;
 plug.id = plug_get_id(plugin);
 str = plug_get_path(plugin);
 e = safe_copy(str, plug.path, sizeof(plug.path), path, "path"); 
 if(e < 0) return;
 
 str = plug_get_oid(plugin);
 e = safe_copy(str, plug.oid, sizeof(plug.oid), path, "oid");
 if(e < 0) return;

 plug.timeout = plug_get_timeout(plugin);
 plug.category = plug_get_category(plugin);

 str = plug_get_name(plugin);
 e = safe_copy(str, plug.name, sizeof(plug.name), path, "name");
 if(e < 0) return;
 
 str = _plug_get_version(plugin);
 e = safe_copy(str, plug.version, sizeof(plug.version), path, "version");
 if(e < 0) return;
 
 
 str = _plug_get_summary(plugin);
 e = safe_copy(str, plug.summary, sizeof(plug.summary), path, "summary");
 if(e < 0) return;
 
 str = _plug_get_description(plugin);
 e = safe_copy(str, plug.description, sizeof(plug.description), path, "description");
 if(e < 0) return;
 
 str = _plug_get_copyright(plugin);
 e = safe_copy(str, plug.copyright, sizeof(plug.copyright), path, "copyright");
 if(e < 0) return;
 
 str = _plug_get_family(plugin);
 e = safe_copy (str, plug.family, sizeof(plug.family), path, "family");
 if(e < 0) return;
 
 str = _plug_get_cve_id(plugin);

 e = safe_copy(str, plug.cve_id, sizeof(plug.cve_id), path, "cve_id");
 if(e < 0) return;
 
 str = _plug_get_bugtraq_id(plugin);
 e = safe_copy(str, plug.bid, sizeof(plug.bid), path, "bugtraq id");
 if(e < 0) return;
 
 str = _plug_get_xref(plugin);
 e = safe_copy(str, plug.xref, sizeof(plug.xref), path, "xref id");
 if(e < 0) return;

 str = _plug_get_tag(plugin);
 e = safe_copy(str, plug.tag, sizeof(plug.tag), path, "tag");
 if(e < 0) return;
 
 arglist = plug_get_deps(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.dependencies, sizeof(plug.dependencies), path, "dependencies");
 efree(&str);
 if(e < 0) return;
 
 arglist = plug_get_required_keys(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.required_keys, sizeof(plug.required_keys), path, "required keys");
 efree(&str);
 if(e < 0) return;
 
 arglist = plug_get_excluded_keys(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.excluded_keys, sizeof(plug.excluded_keys), path, "excluded_keys");
 efree(&str);
 if(e < 0) return;
 
 arglist = plug_get_required_ports(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.required_ports, sizeof(plug.required_ports), path, "required ports");
 efree(&str);
 if(e < 0) return;
 
 arglist = plug_get_required_udp_ports(plugin);
 str = arglist2str(arglist);
 e = safe_copy(str, plug.required_udp_ports, sizeof(plug.required_udp_ports), path, "required udp ports");
 efree(&str);
 if(e < 0) return;

 str = plug_get_sign_key_ids(plugin);
 e = safe_copy(str, plug.sign_key_ids, sizeof(plug.sign_key_ids), path, "key ids of signatures");
 //efree(&str);
 if(e < 0) return;
 
 
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
   if(e < 0) return;
   e = safe_copy(name, pp[num_plugin_prefs].name, sizeof(pp[num_plugin_prefs].name), path, "preference-name");
   if(e < 0) return;
   e = safe_copy(dfl, pp[num_plugin_prefs].dfl, sizeof(pp[num_plugin_prefs].dfl), path, "preference-default");
   if(e < 0) return;
   num_plugin_prefs ++;

   if(num_plugin_prefs >= MAX_PREFS)
   {
    fprintf(stderr, "%s: too many preferences\n", path);
    return;
   }
   _add_plugin_preference(prefs, p_name, name, type, dfl);
   str[0] = '/';
   arglist = arglist->next;
  }
 }
 
 if (num_plugin_prefs > 0)
  plug.has_prefs = 1;
 
 fd = open(desc_file, O_RDWR|O_CREAT|O_TRUNC, 0644);
  if(fd < 0) { // second try: maybe the directory was missing.
    gchar * desc_dir = g_path_get_dirname(desc_file);

    if ((mkdir(desc_dir, 0755) < 0) && (errno != EEXIST)) {
     fprintf(stderr, "mkdir(%s) : %s\n", desc_dir, strerror(errno));
     return;
    }
    g_free(desc_dir);
    fd = open(desc_file, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if(fd < 0) return;
  }
 
  if(write(fd, &plug, sizeof(plug)) < 0)
    perror("write ");
 
  if(num_plugin_prefs > 0)
    write(fd, pp, sizeof(pp));
  close (fd);
 
 arg_set_value(plugin, "preferences", -1, NULL);
 arg_free_all(plugin);

  g_free(desc_file);
  g_free(path);
}

/*---------------------------------------------------------------------*/


char *
store_fetch_path (struct arglist * desc)
{
  char * fname = plug_get_cachefile (desc);
  static struct plugin p;

  store_get_plugin (&p, fname);
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
 char * fname = plug_get_cachefile (desc);
 static struct plugin p;
 struct arglist * ret;

 store_get_plugin (&p, fname);
 ret = str2arglist (p.required_ports);
 return ret;
}

struct arglist *
store_fetch_required_udp_ports (struct arglist * desc)
{
  char * fname = plug_get_cachefile (desc);
  static struct plugin p;
  struct arglist * ret;
  store_get_plugin (&p, fname);
  ret = str2arglist (p.required_udp_ports);
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
