/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Simple JSON reader.
 */

#define _GNU_SOURCE /* See feature_test_macros(7) */
#define _FILE_OFFSET_BITS 64
#include "../base/cvss.h"
#include "../util/jsonpull.h"
#include "openvasd.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief VT categories
 */
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

/**
 * @brief Get the VT category type given the category as string
 *
 * @param cat The category as string.
 *
 * @return Integer representing the category type.
 */
static int
get_category_from_name (const gchar *cat)
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

static void
add_tags_to_nvt (nvti_t *nvt, cJSON *tag_obj)
{
  if (cJSON_IsObject (tag_obj))
    {
      gchar *severity_vector, *str;

      if (!gvm_json_obj_check_str (tag_obj, "affected", &str))
        nvti_set_affected (nvt, str);

      nvti_set_creation_time (nvt, gvm_json_obj_double (tag_obj, "creation_date"));

      nvti_set_modification_time (nvt, gvm_json_obj_double (tag_obj, "last_modification"));

      if (!gvm_json_obj_check_str (tag_obj, "insight", &str))
        nvti_set_insight (nvt, str);

      if (!gvm_json_obj_check_str (tag_obj, "impact", &str))
        nvti_set_impact (nvt, str);

      if (!gvm_json_obj_check_str (tag_obj, "qod", &str))
        nvti_set_qod (nvt, str);

      if (!gvm_json_obj_check_str (tag_obj, "qod_type", &str))
        nvti_set_qod_type (nvt, str);

      if (!gvm_json_obj_check_str (tag_obj, "solution", &str))
        {
          nvti_set_solution (nvt, str);

          if (gvm_json_obj_check_str (tag_obj, "solution_type", &str))
            g_debug ("%s: SOLUTION: missing type for OID: %s", __func__,
                     nvti_oid (nvt));
          else
            nvti_set_solution_type (nvt, str);

          if (!gvm_json_obj_check_str (tag_obj, "solution_method", &str))
            nvti_set_solution_method (nvt, str);
        }

      if (!gvm_json_obj_check_str (tag_obj, "summary", &str))
        nvti_set_summary (nvt, str);

      if (!gvm_json_obj_check_str (tag_obj, "vuldetect", &str))
        nvti_set_detection (nvt, str);

      // Parse severity

      severity_vector = gvm_json_obj_str (tag_obj, "severity_vector");
      if (!severity_vector)
         severity_vector = gvm_json_obj_str (tag_obj, "cvss_base_vector");

      if (severity_vector)
        {
          gchar *severity_type, *cvss_base;
          double cvss_base_dbl;

          if (g_strrstr (severity_vector, "CVSS:3"))
            severity_type = g_strdup ("cvss_base_v3");
          else
            severity_type = g_strdup ("cvss_base_v2");

          cvss_base_dbl = get_cvss_score_from_base_metrics (severity_vector);

          nvti_add_vtseverity (
            nvt, vtseverity_new (severity_type,
                                 gvm_json_obj_str (tag_obj, "severity_origin"),
                                 gvm_json_obj_double (tag_obj, "severity_date"),
                                 cvss_base_dbl, severity_vector));

          nvti_add_tag (nvt, "cvss_base_vector", severity_vector);

          cvss_base = g_strdup_printf (
            "%.1f", get_cvss_score_from_base_metrics (severity_vector));
          nvti_set_cvss_base (nvt, cvss_base);

          g_free (cvss_base);
          g_free (severity_type);
          // end parsing severity
        }
      else
        {
          g_warning ("%s: SEVERITY missing value element", __func__);
          nvti_free (nvt);
          nvt = NULL;
        }
    } // end tag
}

static void
parse_references (nvti_t *nvt, cJSON *vt_obj)
{
  cJSON *item;

  item = cJSON_GetObjectItem (vt_obj, "references");
  if (item != NULL
      && cJSON_IsArray (item))
    {
      cJSON *ref_obj;
      cJSON_ArrayForEach (ref_obj, item)
      {
        gchar *id, *class;

        if (!cJSON_IsObject (ref_obj))
          g_debug ("%s: Error reading VT/REFS reference object", __func__);

        else if (gvm_json_obj_check_str (ref_obj, "class", &class))
          g_warning ("%s: REF missing class attribute", __func__);

        else if (gvm_json_obj_check_str (ref_obj, "id", &id))
          g_warning ("%s: REF missing ID attribute", __func__);

        else
          nvti_add_vtref (nvt, vtref_new (class, id, NULL));
      }
    } // end references
}

static void
add_preferences_to_nvt (nvti_t *nvt, cJSON *vt_obj)
{
  cJSON *item;

  item = cJSON_GetObjectItem (vt_obj, "preferences");
  if (item != NULL)
    {
      if (!cJSON_IsArray (item))
        g_debug ("%s: Error reading VT/REFS array", __func__);
      else
        {
          cJSON *prefs_obj = NULL;

          cJSON_ArrayForEach (prefs_obj, item)
          {
            gchar *class, *name, *default_val;
            int id;

            if (!cJSON_IsObject (prefs_obj))
              g_debug ("%s: Error reading VT/PREFS preference object",
                       __func__);

            else if (gvm_json_obj_check_str (prefs_obj, "class", &class))
              g_warning ("%s: PREF missing class attribute", __func__);

            else if (gvm_json_obj_check_int (prefs_obj, "id", &id))
              g_warning ("%s: PREF missing id attribute", __func__);

            else if (gvm_json_obj_check_str (prefs_obj, "name", &name))
              g_warning ("%s: PREF missing name attribute", __func__);

            else if (gvm_json_obj_check_str (prefs_obj, "default", &default_val))
              g_warning ("%s: PREF missing default attribute", __func__);

            else
              nvti_add_pref (nvt, nvtpref_new (id, name, class, default_val));
          } // end each prefs
        }   // end prefs array
    }       // end preferences
}

/**
 * @brief Parse a VT element given in json format.
 *
 * @param[in]  parser Json pull parser.
 * @param[in]  event  Json pull event.
 * @param[out] nvt    The NVT Info structure to fill with the parsed data.
 *
 * @return 0 on success, 1 on end of feed, -1 on error.
 *         In case of success the nvti struct must be freed with nvti_free()
 *         by the caller.
 */
int
openvasd_parse_vt (gvm_json_pull_parser_t *parser, gvm_json_pull_event_t *event, nvti_t **nvt)
{
  cJSON *vt_obj = NULL;
  gchar *str, *error_message = NULL;
  *nvt = NULL;

  gvm_json_pull_parser_next (parser, event);

  // Handle start/end of json array
  gchar *path = gvm_json_path_to_string (event->path);
  if (!g_strcmp0 (path, "$") && event->type == GVM_JSON_PULL_EVENT_ARRAY_START)
    {
      gvm_json_pull_parser_next (parser, event);
      g_debug ("%s: Start parsing feed", __func__);
    }
  else if (!g_strcmp0 (path, "$")
           && (event->type == GVM_JSON_PULL_EVENT_ARRAY_END
               || event->type == GVM_JSON_PULL_EVENT_EOF))
    {
      g_debug ("%s: Finish parsing feed", __func__);
      g_free (path);
      return 1;
    }
  g_free (path);

  // It is an NVT object
  if (event->type != GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      g_warning ("%s: Error reading VT object", __func__);
      return -1;
    }

  vt_obj = gvm_json_pull_expand_container (parser, &error_message);
  if (!cJSON_IsObject (vt_obj))
    {
      g_free (error_message);
      cJSON_Delete (vt_obj);
      return -1;
    }
  g_free (error_message);

  *nvt = nvti_new ();

  if (gvm_json_obj_check_str (vt_obj, "oid", &str))
    {
      g_warning ("%s: VT missing OID", __func__);
      cJSON_Delete (vt_obj);
      nvti_free (*nvt);
      return -1;
    }
  nvti_set_oid (*nvt, str);

  if (gvm_json_obj_check_str (vt_obj, "name", &str))
    {
      g_warning ("%s: VT missing NAME", __func__);
      cJSON_Delete (vt_obj);
      nvti_free (*nvt);
      return -1;
    }
  nvti_set_name (*nvt, str);

  if (gvm_json_obj_check_str (vt_obj, "family", &str))
    {
      g_warning ("%s: VT missing FAMILY", __func__);
      cJSON_Delete (vt_obj);
      nvti_free (*nvt);
      return -1;
    }
  nvti_set_family (*nvt, str);

  if (gvm_json_obj_check_str (vt_obj, "category", &str))
    {
      g_warning ("%s: VT missing CATEGORY", __func__);
      cJSON_Delete (vt_obj);
      nvti_free (*nvt);
      return -1;
    }
  nvti_set_category (*nvt, get_category_from_name (str));

  cJSON *tag_obj = cJSON_GetObjectItem (vt_obj, "tag");
  if (tag_obj)
    add_tags_to_nvt (*nvt, tag_obj);

  parse_references (*nvt, vt_obj);
  add_preferences_to_nvt (*nvt, vt_obj);
  cJSON_Delete (vt_obj);

  return 0;
}
