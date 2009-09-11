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

#include "share_fd.h"
#include "system.h"
#include "plugutils.h"

#include "nvti.h"

/* for nvticache_t */
#include "nvticache.h"

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

void
_add_plugin_preference (struct arglist *prefs, const char* p_name,
                        const char* name, const char* type, const char* defaul)
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
 // RATS: ignore
 snprintf(pref, strlen(p_name)+10+strlen(type)+strlen(cname), "%s[%s]:%s",
          p_name, type, cname);
 if ( arg_get_value(prefs, pref) == NULL )
  arg_add_value(prefs, pref, ARG_STRING, strlen(defaul), estrdup(defaul));

 efree(&cname);
 efree(&pref);
}

/**
 * @brief Global Handle for NVTI Cache
 */
static nvticache_t * nvti_cache;

/**
 * @brief Initializes the global NVTI Cache.
 *
 * @param dir Path to the cache-directory. It must exist.
 * @param src Path to the plugin-directory. It must exist.
 *
 * @return    0  in case of success (@ref nvti_cache is set now)
 *            -1 if the given path exeeds the buffer size
 *            -2 if the directory does not exist
 *            -3 if the given path was NULL
 *            In any other case than 0 @ref nvti_cache is
 *            not set and a error is printed to stderr
 */
int
store_init (const char * dir, const char * src)
{
  struct stat st;

  if (dir == NULL) {
    fprintf(stderr, "store_init(): called with NULL\n");
    return -3;
  }

  if (stat(dir, &st) < 0) { // check for existance
    fprintf(stderr, "stat(%s): %s\n", dir, strerror(errno));
    return -2;
  }

  nvti_cache = nvticache_new(dir, src);

  if (nvti_cache) return 0;
  return -1;
}

/**
 * @brief Returns a (plugin) arglist assembled from the cached description file
 *
 * @param file Filename of the plugin (e.g. "scriptname1.nasl"
 *             or "subdir1/subdir2/scriptname2.nasl" ).
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
store_load_plugin (const char * file, struct arglist * prefs)
{
  struct arglist * ret;
  struct arglist * al;
  int i;

  nvti_t * n = nvticache_get(nvti_cache, file);
  if (! n) return NULL;

  ret = emalloc (sizeof(struct arglist));
  plug_set_oid (ret, nvti_oid(n));
  plug_set_version (ret, nvti_version(n));
  plug_set_cve_id (ret, nvti_cve(n));
  plug_set_bugtraq_id (ret, nvti_bid(n));
// TODO: these two need exra parameter parsed out
// of the actual string. However, xref and tag
// seem not to appear in the nvti files at all,
// so this needs to be fixed first. 
//  plug_set_xref (ret, nvti_xref(n));
//  plug_set_tag (ret, nvti_tag(n));
  plug_set_summary (ret, nvti_summary(n));
  plug_set_description (ret, nvti_description(n));
  plug_set_copyright (ret, nvti_copyright(n));
  plug_set_family (ret, nvti_family(n));
  plug_set_category (ret, nvti_category(n));
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
  gchar * dummy = g_build_filename (nvti_cache->cache_path, file, NULL);
  gchar * desc_file = g_strconcat (dummy, ".nvti", NULL);
  // assume there is a ".nvti" at the end in the cache path
  gchar * path = g_strdup (file);
  char  * str;
  struct arglist * arglist;

  g_free(dummy);

  if (desc_file == NULL || path == NULL) return; // g_build_filename failed

  nvti_t * n = nvti_new();

  nvti_set_oid(n, plug_get_oid(plugin));
  nvti_set_version(n, plug_get_version(plugin));
  nvti_set_name(n, plug_get_name(plugin));
  nvti_set_summary(n, plug_get_summary(plugin));
  nvti_set_description(n, plug_get_description(plugin));
  nvti_set_copyright(n, plug_get_copyright(plugin));
  nvti_set_cve(n, plug_get_cve_id(plugin));
  nvti_set_bid(n, plug_get_bugtraq_id(plugin));
  nvti_set_xref(n, plug_get_xref(plugin));
  nvti_set_tag(n, plug_get_tag(plugin));
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
  nvti_set_family(n, plug_get_family(plugin));
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
