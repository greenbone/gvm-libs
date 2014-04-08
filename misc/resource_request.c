/* OpenVAS Libraries
 * $Id$
 * Description: Interface to external sources of resource information.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/** @file resource_request.c
 * This module implements an abstract way to describe external sources and
 * fetch resources (strings) from external these sources.
 *
 * The concrete implementation deals with target resources and ldap sources
 * only.
 *
 * The external sources are specified in a key-file.
 */

#include "resource_request.h"

#ifdef ENABLE_LDAP_AUTH
#include "ldap_connect_auth.h"
#endif

#define KEY_ATTRIBUTE   "attribute"
#define KEY_DOMAIN      "domain"
#define KEY_FILTER      "filter"
#define KEY_HOST        "host"
#define KEY_ROOTDN      "rootdn"
#define KEY_SOURCE_TYPE "sourcetype"
#define KEY_USERDN      "userdn"

#define SOURCE_TYPE_LDAP "ldap"

#define TARGET_LOCATOR_FILE_NAME "target.locators"

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib   rer"

/**
 * @brief Request sources for a resource type.
 *
 * @param[in] resourcetype The resource type to find sources for.
 *
 * @return List of source names for resource. Caller has to free list and
 *         contained gchar*s.
 */
GSList *
resource_request_sources (resource_type_t resource_type)
{
  if (resource_type != RESOURCE_TYPE_TARGET)
    return NULL;

  GSList *sources = NULL;
  GKeyFile *key_file = g_key_file_new ();
  gchar *config_file = g_build_filename (OPENVAS_SYSCONF_DIR,
                                         TARGET_LOCATOR_FILE_NAME,
                                         NULL);
  gboolean loaded =
    g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_NONE, NULL);

  gchar **groups = NULL;
  gchar **group = NULL;
  g_free (config_file);

  if (loaded == FALSE)
    {
      g_key_file_free (key_file);
      g_warning ("Target source configuration could not be loaded.\n");
      return NULL;
    }

  groups = g_key_file_get_groups (key_file, NULL);

  group = groups;
  while (*group != NULL)
    {
      sources = g_slist_prepend (sources, g_strdup (*group));
      group++;
    }

  g_key_file_free (key_file);
  g_strfreev (groups);

  return sources;
}


/**
 * @brief Request resources from a source.
 *
 * @param[in] source        Name of the source to use.
 * @param[in] resource_type Type of resource to request.
 * @param[in] username      Username to authenticate with (if needed).
 * @param[in] password      Password to authenticate with (if needed).
 *
 * @return List of resources, NULL in case of error / empty list.
 */
GSList *
resource_request_resource (const gchar * source, resource_type_t resource_type,
                           const gchar * username, const gchar * password)
{
  if (resource_type != RESOURCE_TYPE_TARGET)
    return NULL;

  GSList *resources = NULL;
  GKeyFile *key_file = g_key_file_new ();
  gchar *config_file = g_build_filename (OPENVAS_SYSCONF_DIR,
                                         TARGET_LOCATOR_FILE_NAME,
                                         NULL);
  gchar *value = NULL;

  gboolean loaded =
    g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_NONE, NULL);

  g_free (config_file);

  if (loaded == FALSE)
    {
      g_key_file_free (key_file);
      g_warning ("Target source configuration could not be loaded.");
      return NULL;
    }

  value = g_key_file_get_string (key_file, source, KEY_SOURCE_TYPE, NULL);

  if (value == NULL)
    {
      g_free (value);
      g_key_file_free (key_file);
      g_warning ("Target source configuration misses type.");
      return NULL;
    }

  if (g_ascii_strcasecmp (value, SOURCE_TYPE_LDAP) == 0)
    {
#ifdef ENABLE_LDAP_AUTH
      gchar *userdn = g_key_file_get_string (key_file, source, KEY_USERDN,
                                             NULL);
      gchar *rootdn = g_key_file_get_string (key_file, source, KEY_ROOTDN,
                                             NULL);
      gchar *host = g_key_file_get_string (key_file, source, KEY_HOST, NULL);
      gchar *filter = g_key_file_get_string (key_file, source, KEY_FILTER,
                                             NULL);
      gchar *attribute = g_key_file_get_string (key_file, source,
                                                KEY_ATTRIBUTE, NULL);

      resources =
        ldap_auth_bind_query (host, userdn, username, password, rootdn, filter,
                              attribute);
      g_free (attribute);
      g_free (filter);
      g_free (host);
      g_free (rootdn);
      g_free (userdn);
#else
      g_warning ("LDAP source cannot be used, this openvas-libraries was "
                 "not configured to use openldap.");
#endif /* ENABLE_LDAP_AUTH */
    }
  else
    {
      g_warning ("Source type %s not implemented.", value);
    }

  g_key_file_free (key_file);
  g_free (value);

  return resources;
}
