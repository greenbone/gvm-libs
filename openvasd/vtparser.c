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
      cJSON *item = NULL;
      if ((item = cJSON_GetObjectItem (tag_obj, "affected")) != NULL
          && cJSON_IsString (item))
        nvti_set_affected (nvt, item->valuestring);

      if ((item = cJSON_GetObjectItem (tag_obj, "creation_date")) != NULL
          && cJSON_IsNumber (item))
        nvti_set_creation_time (nvt, item->valuedouble);

      if ((item = cJSON_GetObjectItem (tag_obj, "last_modification")) != NULL
          && cJSON_IsNumber (item))
        nvti_set_modification_time (nvt, item->valuedouble);

      if ((item = cJSON_GetObjectItem (tag_obj, "insight")) != NULL
          && cJSON_IsString (item))
        nvti_set_insight (nvt, item->valuestring);

      if ((item = cJSON_GetObjectItem (tag_obj, "impact")) != NULL
          && cJSON_IsString (item))
        nvti_set_impact (nvt, item->valuestring);

      if ((item = cJSON_GetObjectItem (tag_obj, "qod")) != NULL
          && cJSON_IsString (item))
        nvti_set_qod (nvt, item->valuestring);

      if ((item = cJSON_GetObjectItem (tag_obj, "qod_type")) != NULL
          && cJSON_IsString (item))
        nvti_set_qod_type (nvt, item->valuestring);

      if ((item = cJSON_GetObjectItem (tag_obj, "solution")) != NULL
          && cJSON_IsString (item))
        {
          nvti_set_solution (nvt, item->valuestring);

          if ((item = cJSON_GetObjectItem (tag_obj, "solution_type")) != NULL
              && cJSON_IsString (item))
            nvti_set_solution_type (nvt, item->valuestring);
          else
            g_debug ("%s: SOLUTION: missing type for OID: %s", __func__,
                     nvti_oid (nvt));
          if ((item = cJSON_GetObjectItem (tag_obj, "solution_method")) != NULL
              && cJSON_IsString (item))
            nvti_set_solution_method (nvt, item->valuestring);
        }

      if ((item = cJSON_GetObjectItem (tag_obj, "summary")) != NULL
          && cJSON_IsString (item))
        nvti_set_summary (nvt, item->valuestring);

      if ((item = cJSON_GetObjectItem (tag_obj, "vuldetect")) != NULL
          && cJSON_IsString (item))
        nvti_set_detection (nvt, item->valuestring);

      // Parse severity
      gchar *severity_vector = NULL;

      if ((item = cJSON_GetObjectItem (tag_obj, "severity_vector")) != NULL
          && cJSON_IsString (item))
        severity_vector = item->valuestring;

      if (!severity_vector)
        {
          if ((item = cJSON_GetObjectItem (tag_obj, "cvss_base_vector")) != NULL
              && cJSON_IsString (item))
            severity_vector = item->valuestring;
        }

      if (severity_vector)
        {
          gchar *severity_origin = NULL, *severity_type = NULL;
          gchar *cvss_base;

          time_t severity_date = 0;
          double cvss_base_dbl;

          if (g_strrstr (severity_vector, "CVSS:3"))
            severity_type = g_strdup ("cvss_base_v3");
          else
            severity_type = g_strdup ("cvss_base_v2");

          cvss_base_dbl = get_cvss_score_from_base_metrics (severity_vector);

          if ((item = cJSON_GetObjectItem (tag_obj, "severity_date")) != NULL
              && cJSON_IsNumber (item))
            severity_date = item->valuedouble;

          if ((item = cJSON_GetObjectItem (tag_obj, "severity_origin")) != NULL
              && cJSON_IsString (item))
            severity_origin = item->valuestring;

          nvti_add_vtseverity (
            nvt, vtseverity_new (severity_type, severity_origin, severity_date,
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
  cJSON *item = NULL;
  if ((item = cJSON_GetObjectItem (vt_obj, "references")) != NULL
      && cJSON_IsArray (item))
    {
      cJSON *ref_obj;
      cJSON *ref_item;
      cJSON_ArrayForEach (ref_obj, item)
      {
        gchar *id, *class;

        if (!cJSON_IsObject (ref_obj))
          {
            g_debug ("%s: Error reading VT/REFS reference object", __func__);
            continue;
          }

        if ((ref_item = cJSON_GetObjectItem (ref_obj, "class")) != NULL
            && cJSON_IsString (ref_item))
          {
            class = ref_item->valuestring;
            if ((ref_item = cJSON_GetObjectItem (ref_obj, "id")) == NULL
                && !cJSON_IsString (ref_item))
              {
                g_warning ("%s: REF missing ID attribute", __func__);
                continue;
              }

            id = ref_item->valuestring;
            nvti_add_vtref (nvt, vtref_new (class, id, NULL));
          }
        else
          {
            g_warning ("%s: REF missing type attribute", __func__);
            continue;
          }
      }
    } // end references
}

static void
add_preferences_to_nvt (nvti_t *nvt, cJSON *vt_obj)
{
  cJSON *item = NULL;
  if ((item = cJSON_GetObjectItem (vt_obj, "preferences")) != NULL)
    {
      if (!cJSON_IsArray (item))
        g_debug ("%s: Error reading VT/REFS array", __func__);
      else
        {
          cJSON *prefs_obj = NULL;
          cJSON *prefs_item = NULL;

          cJSON_ArrayForEach (prefs_obj, item)
          {
            gchar *class, *name, *default_val;
            int id;
            if (!cJSON_IsObject (prefs_obj))
              {
                g_debug ("%s: Error reading VT/PREFS preference object",
                         __func__);
                continue;
              }

            if ((prefs_item = cJSON_GetObjectItem (prefs_obj, "class")) == NULL
                || !cJSON_IsString (prefs_item))
              {
                g_warning ("%s: PREF missing class attribute", __func__);
                continue;
              }
            class = prefs_item->valuestring;

            if ((prefs_item = cJSON_GetObjectItem (prefs_obj, "id")) == NULL
                || !cJSON_IsNumber (prefs_item))
              {
                g_warning ("%s: PREF missing id attribute", __func__);
                continue;
              }
            id = prefs_item->valueint;

            if ((prefs_item = cJSON_GetObjectItem (prefs_obj, "name")) == NULL
                || !cJSON_IsString (prefs_item))
              {
                g_warning ("%s: PREF missing name attribute", __func__);
                continue;
              }
            name = prefs_item->valuestring;

            if ((prefs_item = cJSON_GetObjectItem (prefs_obj, "default"))
                  == NULL
                || !cJSON_IsString (prefs_item))
              {
                g_warning ("%s: PREF missing default attribute", __func__);
                continue;
              }
            default_val = prefs_item->valuestring;

            nvti_add_pref (nvt, nvtpref_new (id, name, class, default_val));
          } // end each prefs
        }   // end prefs array
    }       // end preferences
}

/**
 * @brief Parse a VT element given in json format.
 *
 * @param parser Json pull parser.
 * @param event Json pull event.
 *
 * @return nvti structure containing the VT metadata, NULL otherwise.
 *              The nvti struct must be freed with nvti_free() by the caller.
 */
nvti_t *
openvasd_parse_vt (gvm_json_pull_parser_t *parser, gvm_json_pull_event_t *event)
{
  nvti_t *nvt = NULL;
  cJSON *vt_obj = NULL;
  cJSON *item = NULL;
  gchar *error_message = NULL;

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
      return NULL;
    }
  g_free (path);

  // It is an NVT object
  if (event->type != GVM_JSON_PULL_EVENT_OBJECT_START)
    {
      g_warning ("%s: Error reading VT object", __func__);
      return NULL;
    }

  vt_obj = gvm_json_pull_expand_container (parser, &error_message);
  if (!cJSON_IsObject (vt_obj))
    {
      g_free (error_message);
      cJSON_Delete (vt_obj);
      return NULL;
    }

  nvt = nvti_new ();

  if ((item = cJSON_GetObjectItem (vt_obj, "oid")) != NULL
      && cJSON_IsString (item))
    nvti_set_oid (nvt, item->valuestring);
  else
    {
      g_warning ("%s: VT missing OID", __func__);
      cJSON_Delete (vt_obj);
      g_free (error_message);
      nvti_free (nvt);
      return NULL;
    }

  if ((item = cJSON_GetObjectItem (vt_obj, "name")) != NULL
      && cJSON_IsString (item))
    nvti_set_name (nvt, item->valuestring);
  else
    {
      g_warning ("%s: VT missing NAME", __func__);
      cJSON_Delete (vt_obj);
      g_free (error_message);
      nvti_free (nvt);
      return NULL;
    }

  if ((item = cJSON_GetObjectItem (vt_obj, "family")) != NULL
      && cJSON_IsString (item))
    nvti_set_family (nvt, item->valuestring);
  else
    {
      g_warning ("%s: VT missing FAMILY", __func__);
      cJSON_Delete (vt_obj);
      g_free (error_message);
      nvti_free (nvt);
      return NULL;
    }

  if ((item = cJSON_GetObjectItem (vt_obj, "category")) != NULL
      && cJSON_IsString (item))
    nvti_set_category (nvt, get_category_from_name (item->valuestring));
  else
    {
      g_warning ("%s: VT missing CATEGORY", __func__);
      cJSON_Delete (vt_obj);
      g_free (error_message);
      nvti_free (nvt);
      return NULL;
    }

  cJSON *tag_obj = cJSON_GetObjectItem (vt_obj, "tag");
  if (tag_obj)
    add_tags_to_nvt (nvt, tag_obj);

  parse_references (nvt, vt_obj);
  add_preferences_to_nvt (nvt, vt_obj);
  cJSON_Delete (vt_obj);
  g_free (error_message);
  return nvt;
}
