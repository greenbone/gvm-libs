/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Simple JSON reader.
 */

#include "jsonutils.h"

#include "../base/cvss.h"

#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum
{
  ACT_INIT = 0,
  ACT_SCANNER,
  ACT_SETTINGS,
  ACT_GATHER_INFO,
  ACT_ATTACK,
  ACT_MIXED_ATTACK,
  ACT_DESTRUCTIVE_ATTACK,
  ACT_DENIAL,
  ACT_KILL_HOST,
  ACT_FLOOD,
  ACT_END,
} nvt_category;

static int
get_category_from_name (const char *cat)
{
  if (!g_strcmp0 (cat, "init"))
    return ACT_INIT;
  else if (!g_strcmp0 (cat, "scanner"))
    return ACT_SCANNER;
  else if (!g_strcmp0 (cat, "settings"))
    return ACT_SETTINGS;
  else if (!g_strcmp0 (cat, "gather_info"))
    return ACT_GATHER_INFO;
  else if (!g_strcmp0 (cat, "attack"))
    return ACT_ATTACK;
  else if (!g_strcmp0 (cat, "mixed_attack"))
    return ACT_MIXED_ATTACK;
  else if (!g_strcmp0 (cat, "destructive_attack"))
    return ACT_DESTRUCTIVE_ATTACK;
  else if (!g_strcmp0 (cat, "denial"))
    return ACT_DENIAL;
  else if (!g_strcmp0 (cat, "kill_host"))
    return ACT_KILL_HOST;
  else if (!g_strcmp0 (cat, "flood"))
    return ACT_FLOOD;
  else if (!g_strcmp0 (cat, "end"))
    return ACT_END;

  return -1;
}

jparser_t
gvm_parse_jnode (void)
{
  jparser_t parser;
  parser = json_parser_new ();
  return parser;
}

int
gvm_read_jnode (const char *str, jparser_t parse, jreader_t *reade)
{
  JsonParser *parser = parse;

  GError *err = NULL;
  if (!json_parser_load_from_data (parser, str, strlen (str), &err))
    {
      g_warning ("%s: Parsing json string", __func__);
      g_object_unref (parser);
      return -1;
    }

  *reade = (jreader_t) json_reader_new (json_parser_get_root (parser));
  return 0;
}

void
gvm_close_jnode_reader (jreader_t read)
{
  JsonReader *reader = read;
  if (reader)
    g_object_unref (reader);
}

void
gvm_close_jnode_parser (jparser_t parse)
{
  JsonParser *parser = parse;

  if (parser)
    g_object_unref (parser);
}

int
gvm_jnode_count_elements (jreader_t read)
{
  JsonReader *reader = read;

  if (!json_reader_is_array (reader))
    {
      // No results. No information.
      return -1;
    }

  return json_reader_count_elements (reader);
}

nvti_t *
gvm_jnode_parse_vt (jreader_t reader)
{
  nvti_t *nvt = NULL;
  static int element_index = 0;

  if (!json_reader_read_element (reader, element_index))
    {
      g_debug ("%s: Array empty, array end or error", __func__);
      return NULL;
    }

  element_index++;

  if (!json_reader_is_object (reader))
    {
      g_debug ("%s: Error reading VT object", __func__);
      return NULL;
    }

  nvt = nvti_new ();

  if (json_reader_read_member (reader, "oid"))
    {
      nvti_set_oid (nvt, json_reader_get_string_value (reader));
      json_reader_end_member (reader);
    }
  else
    {
      g_warning ("%s: Missing OID", __func__);
      json_reader_end_member (reader);
      nvti_free (nvt);
      return NULL;
    }

  if (json_reader_read_member (reader, "name"))
    {
      nvti_set_name (nvt, json_reader_get_string_value (reader));
      json_reader_end_member (reader);
    }
  else
    {
      g_warning ("%s: VT missing NAME", __func__);
      json_reader_end_member (reader);
      nvti_free (nvt);
      return NULL;
    }

  if (json_reader_read_member (reader, "family"))
    {
      nvti_set_family (nvt, json_reader_get_string_value (reader));
      json_reader_end_member (reader);
    }
  else
    {
      g_warning ("%s: VT missing FAMILY", __func__);
      json_reader_end_member (reader);
      nvti_free (nvt);
      return NULL;
    }

  if (json_reader_read_member (reader, "category"))
    {
      nvti_set_category (
        nvt, get_category_from_name (json_reader_get_string_value (reader)));
      json_reader_end_member (reader);
    }
  else
    {
      g_warning ("%s: VT missing CATEGORY", __func__);
      json_reader_end_member (reader);
      nvti_free (nvt);
      return NULL;
    }

  json_reader_read_member (reader, "tag"); // begin tag

  json_reader_read_member (reader, "affected");
  nvti_set_affected (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "creation_date");
  nvti_set_creation_time (nvt, json_reader_get_int_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "last_modification");
  nvti_set_modification_time (nvt, json_reader_get_int_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "insight");
  nvti_set_insight (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "impact");
  nvti_set_impact (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "qod");
  nvti_set_qod (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "qod_type");
  nvti_set_qod_type (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  if (json_reader_read_member (reader, "solution"))
    {
      nvti_set_solution (nvt, json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      if (json_reader_read_member (reader, "solution_type"))
        {
          nvti_set_solution_type (nvt, json_reader_get_string_value (reader));
          json_reader_end_member (reader);
        }
      else
        {
          g_debug ("%s: SOLUTION: missing type for OID: %s", __func__,
                   nvti_oid (nvt));
          json_reader_end_member (reader);
        }
      json_reader_read_member (reader, "solution_method");
      nvti_set_solution_method (nvt, json_reader_get_string_value (reader));
      json_reader_end_member (reader);
    }

  json_reader_read_member (reader, "summary");
  nvti_set_summary (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  json_reader_read_member (reader, "vuldetect");
  nvti_set_detection (nvt, json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  // Parse severity
  char *severity_vector;

  json_reader_read_member (reader, "severity_vector");
  severity_vector = g_strdup (json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  if (!severity_vector)
    {
      json_reader_read_member (reader, "cvss_base_vector");
      severity_vector = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);
    }

  if (severity_vector)
    {
      char *severity_origin, *severity_type;
      char *cvss_base;

      time_t severity_date;
      double cvss_base_dbl;

      if (g_strrstr (severity_vector, "CVSS:3"))
        severity_type = g_strdup ("cvss_base_v3");
      else
        severity_type = g_strdup ("cvss_base_v2");

      cvss_base_dbl = get_cvss_score_from_base_metrics (severity_vector);

      json_reader_read_member (reader, "severity_date");
      severity_date = json_reader_get_int_value (reader);
      json_reader_end_member (reader);

      json_reader_read_member (reader, "severity_origin");
      severity_origin = g_strdup (json_reader_get_string_value (reader));
      json_reader_end_member (reader);

      nvti_add_vtseverity (nvt, vtseverity_new (severity_type, severity_origin,
                                                severity_date, cvss_base_dbl,
                                                severity_vector));

      nvti_add_tag (nvt, "cvss_base_vector", severity_vector);

      cvss_base = g_strdup_printf (
        "%.1f", get_cvss_score_from_base_metrics (severity_vector));
      nvti_set_cvss_base (nvt, cvss_base);

      g_free (cvss_base);
      g_free (severity_vector);
      g_free (severity_origin);
      g_free (severity_type);
      // end parsing severity
    }
  else
    {
      g_warning ("%s: SEVERITY missing value element", __func__);
      nvti_free (nvt);
      return NULL;
    }

  json_reader_end_member (reader); // end tag

  // Parse references
  if (json_reader_read_member (reader, "references"))
    {
      if (!json_reader_is_array (reader))
        {
          g_debug ("%s: Error reading VT/REFS array", __func__);
          json_reader_end_member (reader);
        }
      else
        {
          int count = json_reader_count_elements (reader);
          for (int j = 0; j < count; j++)
            {
              char *id, *class;
              json_reader_read_element (reader, j);
              if (!json_reader_is_object (reader))
                {
                  g_debug ("%s: Error reading VT/REFS reference object",
                           __func__);
                  json_reader_end_element (reader);
                  continue;
                }
              if (!json_reader_read_member (reader, "class"))
                {
                  g_warning ("%s: REF missing type attribute", __func__);
                  json_reader_end_member (reader);
                  json_reader_end_element (reader);
                  continue;
                }
              else
                {
                  class = g_strdup (json_reader_get_string_value (reader));
                  json_reader_end_member (reader);

                  if (!json_reader_read_member (reader, "id"))
                    {
                      g_warning ("%s: REF missing ID attribute", __func__);
                      json_reader_end_member (reader);
                      json_reader_end_element (reader);
                      g_free (class);
                      continue;
                    }

                  id = g_strdup (json_reader_get_string_value (reader));
                  nvti_add_vtref (nvt, vtref_new (class, id, NULL));
                  json_reader_end_member (reader);
                  json_reader_end_element (reader);
                  g_free (class);
                  g_free (id);
                }
            }
        }
    }
  json_reader_end_member (reader); // End references

  // Parse preferences
  if (json_reader_read_member (reader, "preferences"))
    {
      if (!json_reader_is_array (reader))
        {
          g_debug ("%s: Error reading VT/REFS array", __func__);
          json_reader_end_member (reader);
        }
      else
        {
          int count = json_reader_count_elements (reader);
          for (int j = 0; j < count; j++)
            {
              char *class, *name, *default_val;
              int id;

              json_reader_read_element (reader, j);
              if (!json_reader_is_object (reader))
                {
                  g_debug ("%s: Error reading VT/PREFS preference object",
                           __func__);
                  json_reader_end_element (reader);
                  continue;
                }

              if (!json_reader_read_member (reader, "class"))
                {
                  g_warning ("%s: PREF missing type attribute", __func__);
                  json_reader_end_member (reader);
                  json_reader_end_element (reader);
                  continue;
                }
              else
                {
                  class = g_strdup (json_reader_get_string_value (reader));
                  json_reader_end_member (reader);
                }

              if (!json_reader_read_member (reader, "id"))
                {
                  g_warning ("%s: PREF missing id attribute", __func__);
                  json_reader_end_member (reader);
                  json_reader_end_element (reader);
                  g_free (class);
                  continue;
                }
              else
                {
                  id = json_reader_get_int_value (reader);
                  json_reader_end_member (reader);
                }

              if (!json_reader_read_member (reader, "name"))
                {
                  g_warning ("%s: PREF missing name attribute", __func__);
                  json_reader_end_member (reader);
                  json_reader_end_element (reader);
                  g_free (class);
                  continue;
                }
              else
                {
                  name = g_strdup (json_reader_get_string_value (reader));
                  json_reader_end_member (reader);
                }

              if (!json_reader_read_member (reader, "default"))
                {
                  g_warning ("%s: PREF missing default value attribute",
                             __func__);
                  json_reader_end_member (reader);
                  json_reader_end_element (reader);
                  g_free (class);
                  g_free (name);
                  continue;
                }
              else
                {
                  default_val =
                    g_strdup (json_reader_get_string_value (reader));
                  json_reader_end_member (reader);
                }

              nvti_add_pref (nvt, nvtpref_new (id, name, class, default_val));
              json_reader_end_element (reader); // finish preference
              g_free (class);
              g_free (name);
              g_free (default_val);
            }
        }
    }
  json_reader_end_member (reader);  // End preferences
  json_reader_end_element (reader); // End vt

  return nvt;
}
