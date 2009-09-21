/* OpenVAS-Client
 *
 * Description: Functions for Severity Filters.
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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


/** @file
 *
 * Implementaiton of Severity Filters.
 *
 * Severity filters consist of a set of severity overrides.
 * The data is stored in a xml file, here is a sample:
 *
 * @verbatim
<severity_filter name="My Severity Filter">
  <severity_override name="SeverityOverride1"
                     host="localhost"
                     port="general/tcp"
                     OID="1.3.6.1.4.1.25623.1.0.19506"
                     severity_from="warning"
                     severity_to="FP"
                     active="true">
    <reason>
      This is just a test-override.
    </reason>
  </severity_override>
  <severity_override name="SeverityOverride2"
                     host="localhost"
                     port="general/tcp"
                     OID="1.3.6.1.4.1.25623.1.0.19507"
                     severity_from="warning"
                     severity_to="FP"
                     active="true">
    <reason>
      This is just another test-override.
      With some more reasons.
    </reason>
  </severity_override>
</severity_filter>
@endverbatim
 *
 * The file is tried to be in sync with the filter, every call to
 * severity_filter_add or severity_filter_remove will also save the file.
 */

#include "severity_filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define XML_ELEM_SEVERITY_FILTER "severity_filter"
#define XML_ELEM_SEVERITY_OVERRIDE "severity_override"
#define XML_ELEM_REASON "reason"
#define XML_ATTR_NAME "name"
#define XML_ATTR_HOST "host"
#define XML_ATTR_PORT "port"
#define XML_ATTR_OID "OID"
#define XML_ATTR_SEVERITY_FROM "severity_from"
#define XML_ATTR_SEVERITY_TO "severity_to"
#define XML_ATTR_ACTIVE "active"
#define XML_ATTR_ACTIVE_TRUE "true"

/** @todo Resolve workaround, real i18n */
#define _(abc) abc

/* temporary, should be part of the global context */
/* initialized in two cases: severity filtering dialog and severity filtering activation (both in extra menu) */
severity_filter_t * global_filter = NULL;

static gboolean severity_filter_to_xml (const severity_filter_t * filter);

/**
 * @brief Creates a new severity override.
 * 
 * If any of the parameter equals NULL, NULL will be returned.
 * The severity_override will be returned enabled (active == TRUE).
 * 
 * @return If none of the parameters equalled NULL, returns fresh
 *         severity_override, NULL otherwise.
 */
const severity_override_t *
severity_override_new (const gchar * name, const gchar * host,
                       const gchar * port, const gchar * oid,
                       const gchar * reason, const gchar * severity_from,
                       const gchar * severity_to, gboolean active)
{
  if (name == NULL || host == NULL || port == NULL || oid == NULL
      || reason == NULL || severity_from == NULL || severity_to == NULL)
    return NULL;

  severity_override_t* override = g_malloc (sizeof (severity_override_t));
  override->name = g_strdup (name);
  override->host = g_strdup (host);
  override->port = g_strdup (port);
  override->OID  = g_strdup (oid);
  override->reason    = g_strdup (reason);
  override->severity_from = g_strdup (severity_from);
  override->severity_to   = g_strdup (severity_to);
  override->active        = active;

  return override;
}

/**
 * @brief Duplicates a severity_override.
 * 
 * @param override The severity_override to duplicate.
 * 
 * @return Duplicate of override or NULL if override is underspecified.
 */
const severity_override_t*
severity_override_duplicate (const severity_override_t* override)
{
  return severity_override_new (override->name, override->host, override->port,
                                override->OID, override->reason,
                                override->severity_from, override->severity_to,
                                override->active);
}


/**
 * @brief Frees the severity_override and all its associated data.
 */
void
severity_override_free (severity_override_t * override)
{
  if (override == NULL) return;

  if (override->name != NULL) g_free (override->name);
  if (override->host != NULL) g_free (override->host);
  if (override->port != NULL) g_free (override->port);
  if (override->OID != NULL)  g_free (override->OID);
  if (override->reason != NULL) g_free (override->reason);
  if (override->severity_from != NULL) g_free (override->severity_from);
  if (override->severity_to != NULL) g_free (override->severity_to);
  g_free (override);
}


/**
 * @brief Creates a new empty severity_filter with a name.
 * 
 * Note that if a file with the filename parameter already exists, the file will
 * be overwritten.
 * 
 * @param name    User-defined name for the severity_filter.
 * @param filname Storage location for the severity_filter (no checks performed).
 * 
 * @return Fresh, named severity_filter.
 */
severity_filter_t *
severity_filter_new (const gchar* name, const gchar* filename)
{
  if (name == NULL || filename == NULL)
    return NULL;

  severity_filter_t* filter = g_malloc (sizeof(severity_filter_t));
  filter->overrides = NULL;
  filter->name = g_strdup (name);
  filter->filename = g_strdup (filename);

  return(filter);
}


/**
 * @brief Frees the severity filter and all overrides it contains.
 *
 * @param filter The filter to be free'd.
 */
void severity_filter_free (severity_filter_t* filter)
{
  g_free (filter->name);
  g_free (filter->filename);

  g_slist_foreach (filter->overrides, (GFunc)severity_override_free, NULL);

  g_free (filter);
}


/**
 * @brief Applies the global filter to the given alert.
 * 
 * @param host Name of the host for the alert.
 * @param port Port of the alert.
 * @param oid  OID of the NVT that produced the alert.
 * @param severity Severity that was given by the NVT.
 * 
 * This function iterates over all severity overrides
 * of the global filter. If a match of host, port, oid
 * and severity is found, then the overriding severity is
 * returned.
 *
 * @return NULL in case no suitable filter rule was found or any parameter
 *         equals NULL.
 *         Else a string with the new severity is returned.
 */
const gchar *
severity_filter_apply (const gchar * host, const gchar * port,
                       const gchar * oid, const gchar * severity)
{
  if (global_filter == NULL
      || host == NULL || port == NULL || oid == NULL || severity == NULL)
    {
      return NULL;
    }

  GSList * o = g_slist_nth(global_filter->overrides, 0);

  while (o) {
    // Check matches. Optimization possible as probably many strings are
    // compared against always the same strings or patterns. However, we do not
    // want to carry compiled versions of the patterns around.
    if ( g_pattern_match_simple (((severity_override_t *)o->data)->host, host) == TRUE &&
         g_pattern_match_simple (((severity_override_t *)o->data)->port, port) == TRUE &&
        (!strcmp(oid, ((severity_override_t *)o->data)->OID)) &&
        (!strcmp(severity, ((severity_override_t *)o->data)->severity_from)))
      return ((severity_override_t *)o->data)->severity_to;
    o = g_slist_next(o);
  }

  return NULL;
}


/**
 * @brief Similarity predicate to indicate whether two overrides conflict.
 * 
 * Actually an implementation of a GCompareFunc, to be used in a
 * g_slist_find_custom ().
 * Two conflicting overrides have the same OID, host, port and severity_from.
 * 
 * @param override1 severity_override to compare against override2.
 * @param override1 severity_override to compare against override1.
 * 
 * @return 0 if the two overrides conflict, 1 if they do not conflict or at
 *         least on is NULL.
 */
static gint
severity_override_similarity_predicate (const severity_override_t* override1,
                                        const severity_override_t* override2)
{
  if (override1 == NULL || override2 == NULL)
    return 1;

  if (   !strcmp(override1->OID,           override2->OID)
      && !strcmp(override1->host,          override2->host)
      && !strcmp(override1->port,          override2->port)
      && !strcmp(override1->severity_from, override2->severity_from))
    return 0;
  else return 1;
}


/**
 * @brief Returns TRUE if a similar (in the sense of the
 * @brief severity_override_similarity_predicate) override is contained in a
 * @brief filter.
 * 
 * @param filter   The filter to ask if its overrides conflict against the
 *                 override.
 * @param override The questinable override.
 * 
 * @return TRUE if the override should not be added because of a conflict-to-be,
 *         FALSE otherwise or if one of the arguments is NULL.
 */
gboolean
severity_filter_contains_conflicting_override (const severity_filter_t* filter,
                                               const severity_override_t* override)
{
  // No filter, override or conflict?
  if (filter == NULL || override == NULL
      || (g_slist_find_custom (filter->overrides, override, (GCompareFunc) severity_override_similarity_predicate)
                             == NULL))
      return FALSE;

  return TRUE;
}

/**
 * @brief Returns TRUE if a severity_override with given parameters exist
 * @brief already in a filter.
 * 
 * @param filter   The filter to ask if its overrides conflict against the
 *                 override.
 * @param host     Hostname of eventually conflicting severity_override.
 * @param port     Port of eventually conflicting severity_override.
 * @param oid      OID of NVT in eventually conflicting severity_override.
 * @param from     Severity-to-be-overriden of eventually conflicting
 *                 severity_override.
 * 
 * @return TRUE if an override wiht given parameter should not be added because
 *         of a conflict-to-be, FALSE otherwise or if one of the arguments is NULL.
 */
gboolean
severity_filter_contains_conflicting (const severity_filter_t* filter,
                                      const gchar* host, const gchar* port,
                                      const gchar* oid,  const gchar* from)
{
  if (filter == NULL || host == NULL || port == NULL || oid == NULL || from == NULL)
    return FALSE;

  severity_override_t* override = NULL;
  GSList* walk = filter->overrides;
  while (walk)
    {
      override = walk->data;
      if (   !strcmp (override->host, host)
          && !strcmp (override->port, port)
          && !strcmp (override->OID, oid)
          && !strcmp (override->severity_from , from))
        return TRUE;
      walk = g_slist_next (walk);
    }

  return FALSE;
}


/**
 * @brief Adds a severity_override to a severity_filter and saves its
 * @brief representation to disk.
 * 
 * It is assumed that an override is added only once to a filter
 * - severity_filter_remove might otherwise create a mess.
 * 
 * @param filter   The severity_filter to add a override to.
 * @param override The severity_override to add to the filter.
 *                 The object is used directly, no copy created.
 *                 Upon free'ing the filter, the override will be
 *                 free'd as well.
 * 
 * @return FALSE in case the add operation failed (e.g. file not found), else
 * @return TRUE.
 */
gboolean
severity_filter_add (severity_filter_t * filter,
                     const severity_override_t * override)
{
  if (filter == NULL || override == NULL)
    return FALSE;

  filter->overrides = g_slist_prepend (filter->overrides, (void*) override);

  return severity_filter_to_xml (filter);
}




/**
 * @brief Removes and frees a override from a filter and saves the filter to
 * @brief disk.
 * 
 * Note that is assumed that the same override has not been added twice to
 * a severity_filter.
 * 
 * @param filter   The filter from wich to remove the override.
 * @param override The override to remove from the filter.
 * 
 * @return TRUE if file-writing was successfull, FALSE otherwise.
 */
gboolean
severity_filter_remove (severity_filter_t* filter, severity_override_t* override)
{
  filter->overrides = g_slist_remove (filter->overrides, override);
  severity_override_free (override);
  return severity_filter_to_xml (filter);
}

/**
 * @brief In a list- callback write a severity override xml-element to file.
 * 
 * @param override The override to write an xml-element for.
 * @param fd       The file descriptor to write to.
 */
static void
write_override_xml_elem (severity_override_t* override, FILE* fd)
{
  if (!fd) return;

  gchar* override_elem = g_markup_printf_escaped (
                           "\t<severity_override name=\"%s\"\n"
                           "\t\thost=\"%s\"\n"
                           "\t\tport=\"%s\"\n"
                           "\t\tOID=\"%s\"\n"
                           "\t\tseverity_from=\"%s\"\n"
                           "\t\tseverity_to=\"%s\"\n"
                           "\t\tactive=\"%s\">\n",
                            override->name, override->host,override->port,
                            override->OID, override->severity_from,
                            override->severity_to,
                            (override->active == TRUE)? "true" : "false");

  gchar* reason_elem = g_markup_printf_escaped ("\t\t<reason>\n\t\t%s\n\t\t</reason>\n",
                                                override->reason);

  fprintf (fd, "%s", override_elem);
  fprintf (fd, "%s", reason_elem);
  fprintf (fd, "%s", "\t</severity_override>\n");

  g_free (override_elem);
  g_free (reason_elem);
}


/**
 * @brief Export a severity_filter to xml, so that it can be read in with
 * @brief severity_filter_from_xml.
 * 
 * An examplary file is included in the documentation for this file.
 * 
 * @param severity_filter The severity_fiter to export.
 * 
 * @return TRUE in case the filte was successfully created, else FALSE.
 */
static gboolean
severity_filter_to_xml (const severity_filter_t * filter)
{
  FILE* fd;

  if (filter == NULL) return FALSE;

  fd = fopen (filter->filename, "w");
  if (fd <= 0) return FALSE;

  gchar* filter_start_elem = g_markup_printf_escaped ("<severity_filter name=\"%s\">\n", filter->name);
  fprintf (fd, "%s", filter_start_elem);
  g_slist_foreach (filter->overrides, (GFunc) write_override_xml_elem , fd);
  fprintf (fd, "</severity_filter>");
  g_free (filter_start_elem);

  fclose (fd);
  return TRUE;
}

/**
 * @brief Modifies a severity_filter from lists of (xml) attribute names and
 * @brief values (sets name).
 * 
 * A line in an xml file describing a filter looks like:
 * @verbatim <severity_filter name="My Severity Filter"> @endverbatim
 * Thus, only one attribute- value pair is needed (\"name\"), others will be
 * ignored.
 * 
 * @param attr_name   Attribute names, e.g. {"name", NULL}.
 * @param attr_values Attribute values, e.g. {"My Name", NULL}.
 * @param filter      The filter whose attributes to set.
 */
static void
severity_filter_xml_elem (const gchar** attr_names, const gchar** attr_values,
                          severity_filter_t* filter)
{
  while (*attr_names != NULL) {
    if (!strcmp (*attr_names, XML_ATTR_NAME) && *attr_values != NULL)
      filter->name = g_strdup(*attr_values);
    ++attr_values;
    ++attr_names;
  }
}


/**
 * @brief Creates a override from lists of (xml) attribute names and values.
 * 
 * The reason will be the empty string, the source xml should look like:
 * @verbatim
 * <severity_override name="SeverityOverride2" host="192.168.11.35" port="general/tcp" OID="1.3.6.1.4.1.25623.1.0.900505"
      severity_from="NOTE" severity_to="FALSE" active="true"> @endverbatim
 * If any attribute is missing, NULL will be returned.
 * 
 * @return A fresh severity_override_t if all attributes and values were found
 *         in the parameter lists.
 */
static const severity_override_t*
severity_override_xml_elem (const gchar** attr_names, const gchar** attr_values)
{
  const severity_override_t* override = NULL;
  const gchar *name = NULL,
              *host = NULL,
              *port = NULL,
              *oid  = NULL,
              *severity_from = NULL,
              *severity_to = NULL;
  gboolean active = FALSE;

  while (*attr_names != NULL) {
    if (!strcmp (*attr_names, XML_ATTR_NAME) && *attr_values != NULL)
      name = *attr_values;
    else if (!strcmp (*attr_names, XML_ATTR_HOST) && *attr_values != NULL)
      host = *attr_values;
    else if (!strcmp (*attr_names, XML_ATTR_PORT) && *attr_values != NULL)
      port = *attr_values;
    else if (!strcmp (*attr_names, XML_ATTR_OID) && *attr_values != NULL)
      oid = *attr_values;
    else if (!strcmp (*attr_names, XML_ATTR_SEVERITY_FROM) && *attr_values != NULL)
      severity_from = *attr_values;
    else if (!strcmp (*attr_names, XML_ATTR_SEVERITY_TO) && *attr_values != NULL)
      severity_to = *attr_values;
    else if (!strcmp (*attr_names, XML_ATTR_ACTIVE) && *attr_values != NULL)
      active = (!strcmp (*attr_values, XML_ATTR_ACTIVE_TRUE)) ? TRUE : FALSE;

    ++attr_values;
    ++attr_names;
  }

  override = severity_override_new (name, host, port, oid, "", severity_from,
                                    severity_to, active);

  return override;
}


/**
 * @brief Used as an GMarkupParsers start_element function.
 * 
 * We are interested in filter and override elements, as they contain
 * the important attributes.
 * 
 * When parsing went fine, (*user_data) will point to a severity_filter
 * that contains all the severity_overrides defined in an xml file.
 * 
 * @param user_data[in,out] Double-pointer to a severity_filter_t.
 */
static void
severity_filter_xml_start_element (GMarkupParseContext *context,
                                   const gchar *element_name,
                                   const gchar **attribute_names,
                                   const gchar **attribute_values,
                                   gpointer user_data, GError **error)
{
  severity_filter_t* filter = user_data;

  /* Its a: <severity_filter name="My severity Filter"> */
  if (!strcmp (element_name, XML_ELEM_SEVERITY_FILTER)) {
    if (filter->name != NULL)
      printf (_("XML parser error: second filter specified in file\n"));

    severity_filter_xml_elem (attribute_names, attribute_values, filter);

    if (filter->name == NULL)
      printf (_("XML parser error: error parsing filter element\n"));
  }
  /* Its a: <severity_override name="SeverityOverride2" host="192.168.11.35"
                  port="general/tcp" OID="1.3.6.1.4.1.25623.1.0.900505"
                  severity_from="NOTE" severity_to="FALSE" active="true"> ...  */
  else if (!strcmp (element_name, XML_ELEM_SEVERITY_OVERRIDE))
  {
    if (filter != NULL) {
      const severity_override_t* override =
        severity_override_xml_elem (attribute_names, attribute_values);
      if (override != NULL)
        filter->overrides = g_slist_prepend (filter->overrides, (void*) override);
      else printf (_("XML Parser Error: override parsing error\n"));
    } else
      printf (_("XML Parser Error: override without filter\n"));
  }
}


/**
 * @brief Used as a GMarkupParser text- function.
 * 
 * We are just interested in the text between the reason elements, ignore
 * everything else.
 * The text between reason start/end elements will be set as reason for the
 * last added override in the filter that is parsed.
 * 
 * @param [in,out] user_data The severity_filter that is currently parsed.
 */
static void
severity_override_xml_reason_text (GMarkupParseContext *context,
                                   const gchar *text,
                                   gsize text_len, gpointer user_data,
                                   GError **error)
{
  severity_filter_t* filter = user_data;
  if (!strcmp (g_markup_parse_context_get_element (context), XML_ELEM_REASON)
      && filter != NULL 
      && filter->overrides != NULL
      && filter->overrides->data != NULL)
  {
    severity_override_t* override = filter->overrides->data;
    g_free (override->reason);
    override->reason = g_strstrip (g_strdup (text));
  }
  // Else either not in a reason element or no override to set reason for.
  // Later case should be handled as an error.
}


/**
 * @brief Imports a severity_filter from an xml file that has been written by
 * @brief severity_filter_to_xml.
 * 
 * An examplary xml file is included in the documentation for this file.
 * 
 * @param filename Path of file to parse.
 * 
 * @return If the file exists and error while parsing occured, a fresh
 *         severity_filter as described in the file (parameter), NULL otherwise.
 */
severity_filter_t *
severity_filter_from_xml (const gchar * filename)
{
  GMarkupParser parser;
  GMarkupParseContext *context = NULL;
  gchar *filebuffer = NULL;
  gsize length = 0;
  severity_filter_t* filter = malloc (sizeof (severity_filter_t));
  filter->filename = g_strdup (filename);
  filter->overrides = NULL;
  filter->name = NULL;

  if (!g_file_get_contents (filename, &filebuffer, &length, NULL))
    {
      g_free (filter->filename);
      free (filter);
      return NULL;
    }

  // Init XML subset parser
  parser.start_element = severity_filter_xml_start_element;
  parser.end_element   = NULL;
  parser.text          = severity_override_xml_reason_text;
  parser.passthrough   = NULL;
  parser.error         = NULL;

  // Setup context and parse it
  context = g_markup_parse_context_new (&parser, 0, filter, NULL);
  if (g_markup_parse_context_parse (context, filebuffer, length, NULL) == TRUE)
  {
#ifdef DEBUG
    if (filter) {
      printf ("Parsing of severity- XML (%s) done.\n", filter->name);
      if (filter->overrides) {
        severity_override_t* override = filter->overrides->data;
        printf ("\tFirst override: %s\n", override->name);
        printf ("\treason %s\n", override->reason);
      }
    } else
      printf ("Parsing severity- XML succeeded but no valid filter found.\n");
#endif
  } else printf(_("XML Parser error: Parsing failed"));

  g_free (filebuffer);
  g_markup_parse_context_free (context);

  if (filter->name == NULL)
    {
      severity_filter_free (filter);
      filter = NULL;
    }

  return filter;
}
