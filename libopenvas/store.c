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

#include "nvti.h"

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
 char * t;

 if(!str || str[0] == '\0')
  {
   return NULL;
  }

 t = strchr(str, ',');

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
  gchar * desc_file = g_strconcat (dummy, ".nvti", NULL);

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

  nvti_t * n = nvti_from_keyfile(desc_file);

  ret = emalloc (sizeof(struct arglist));
  plug_set_oid (ret, nvti_oid(n));
  plug_set_category (ret, nvti_category(n));
  plug_set_cachefile (ret, desc_file);
  plug_set_path (ret, nvti_src(n));
  plug_set_family (ret, nvti_family(n));
  plug_set_sign_key_ids (ret, nvti_sign_key_ids(n));

  al = str2arglist (nvti_required_ports(n));
  if (al != NULL) arg_add_value (ret, "required_ports", ARG_ARGLIST, -1, al);

  al = str2arglist (nvti_required_keys(n));
  if (al != NULL) arg_add_value (ret, "required_keys", ARG_ARGLIST, -1, al);

  al = str2arglist (nvti_mandatory_keys(n));
  if (al != NULL) arg_add_value (ret, "mandatory_keys", ARG_ARGLIST, -1, al);

  al = str2arglist (nvti_required_udp_ports(n));
  if (al != NULL) arg_add_value (ret, "required_udp_ports", ARG_ARGLIST, -1, al);

  al = str2arglist (nvti_excluded_keys(n));
  if (al != NULL) arg_add_value (ret, "excluded_keys", ARG_ARGLIST, -1, al);

  al = str2arglist (nvti_dependencies(n));
  if (al != NULL) arg_add_value (ret, "DEPENDENCIES", ARG_ARGLIST, -1, al);

  if (nvti_timeout(n) != 0) arg_add_value (ret, "TIMEOUT", ARG_INT, -1, GSIZE_TO_POINTER(nvti_timeout(n)));

  arg_add_value (ret, "NAME", ARG_STRING, strlen(nvti_name(n)), estrdup(nvti_name(n)));

  arg_add_value (ret, "preferences", ARG_ARGLIST, -1, prefs);

  for (i=0;i < nvti_pref_len(n);i ++) {
    nvtpref_t * np = nvti_pref(n, i);
    _add_plugin_preference (prefs, nvti_name(n), nvtpref_name(np), nvtpref_type(np), nvtpref_default(np));
  }

  nvti_free(n);
  g_free(desc_file);

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
  gchar * desc_file = g_strconcat (dummy, ".nvti", NULL);
  // assume there is a ".nvti" at the end in the store_dir path
  gchar * path = g_strdup (file);
  char  * str;
  struct arglist * arglist;

  g_free(dummy);

  if (desc_file == NULL || path == NULL) return; // g_build_filename failed

  nvti_t * n = nvti_new();

  nvti_set_oid(n, plug_get_oid(plugin));
  nvti_set_version(n, _plug_get_version(plugin));
  nvti_set_name(n, plug_get_name(plugin));
  nvti_set_summary(n, _plug_get_summary(plugin));
  nvti_set_description(n, _plug_get_description(plugin));
  nvti_set_copyright(n, _plug_get_copyright(plugin));
  nvti_set_cve(n, _plug_get_cve_id(plugin));
  nvti_set_bid(n, _plug_get_bugtraq_id(plugin));
  nvti_set_xref(n, _plug_get_xref(plugin));
  nvti_set_tag(n, _plug_get_tag(plugin));
  str = arglist2str(plug_get_deps(plugin));
  nvti_set_dependencies(n, str);
  efree(&str);
  str = arglist2str(plug_get_required_keys(plugin));
  nvti_set_required_keys(n, str);
  efree(&str);
  str = arglist2str(plug_get_mandatory_keys(plugin));
  nvti_set_mandatory_keys(n, str);
  efree(&str);
  str = arglist2str(plug_get_excluded_keys(plugin));
  nvti_set_excluded_keys(n, str);
  efree(&str);
  str = arglist2str(plug_get_required_ports(plugin));
  nvti_set_required_ports(n, str);
  efree(&str);
  str = arglist2str(plug_get_required_udp_ports(plugin));
  nvti_set_required_udp_ports(n, str);
  efree(&str);
  nvti_set_sign_key_ids(n, plug_get_sign_key_ids(plugin));
  nvti_set_family(n, _plug_get_family(plugin));
  nvti_set_src(n, plug_get_path(plugin));
  nvti_set_timeout(n, plug_get_timeout(plugin));
  nvti_set_category(n, plug_get_category(plugin));

  arglist = arg_get_value(plugin, "PLUGIN_PREFS");
  if( arglist != NULL )
  {
    while(arglist->next != NULL)
    {
      nvtpref_t * np;
      char * name = arglist->name;
      char * dfl = arglist->value;
      char * type, * str;

      type = arglist->name;
      str = strchr(type, '/');
      str[0] = '\0';
      name = str + 1;

      np = nvtpref_new(name, type, dfl); 
      nvti_add_pref(n, np);

      str[0] = '/';
      arglist = arglist->next;
    }
  }

  nvti_to_keyfile(n, desc_file);
  nvti_free(n);

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

  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_src(n));
}

char * store_fetch_version(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_version(n));
}

char * store_fetch_summary(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_summary(n));
}

char * store_fetch_description(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_description(n));
}

int store_fetch_category(struct arglist * desc)
{
 return plug_get_category(desc);
}

char * store_fetch_copyright(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_copyright(n));
}

char * store_fetch_family(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_family(n));
}

char * store_fetch_oid(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_oid(n));
}

char * store_fetch_cve_id(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_cve(n));
}

char * store_fetch_bugtraq_id(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_bid(n));
}


char * store_fetch_xref(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_xref(n));
}

char * store_fetch_tag(struct arglist * desc)
{
  char * fname = plug_get_cachefile(desc);
 
  nvti_t * n = nvti_from_keyfile(fname);

  return(nvti_tag(n));
}
