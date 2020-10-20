/* Copyright (C) 2012-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

/**
 * @file
 * @brief CVSS utility functions
 *
 * This file contains utility functions for handling CVSS.
 * Namels a calculator for the CVSS base score from a CVSS base
 * vector.
 *
 * The base equation is the foundation of CVSS scoring. The base equation is:
 * BaseScore6
 *   = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)–1.5)*f(Impact))
 *
 * Impact
 *   = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
 *
 * Exploitability
 *   = 20* AccessVector*AccessComplexity*Authentication
 *
 * f(impact)= 0 if Impact=0, 1.176 otherwise
 * AccessVector     = case AccessVector of
 *                       requires local access: 0.395
 *                       adjacent network accessible: 0.646
 *                       network accessible: 1.0
 * AccessComplexity = case AccessComplexity of
 *                       high: 0.35
 *                       medium: 0.61
 *                       low: 0.71
 * Authentication   = case Authentication of
 *                       requires multiple instances of authentication: 0.45
 *                       requires single instance of authentication: 0.56
 *                       requires no authentication: 0.704
 * ConfImpact       = case ConfidentialityImpact of
 *                       none:              0.0
 *                       partial:           0.275
 *                       complete:          0.660
 * IntegImpact      = case IntegrityImpact of
 *                       none:              0.0
 *                       partial:           0.275
 *                       complete:          0.660
 * AvailImpact      = case AvailabilityImpact of
 *                       none:              0.0
 *                       partial:           0.275
 *                       complete:          0.660
 */

#include <glib.h>
#include <math.h>
#include <string.h>

/* Static Headers. */

static double
get_cvss_score_from_base_metrics_v3 (const char *);

/* CVSS v2. */

// clang-format off
/**
 * @brief AccessVector (AV) Constants.
 */
#define AV_NETWORK          1.0   /**< Access Vector Network. */
#define AV_ADJACENT_NETWORK 0.646 /**< Access Vector Adjacent Network. */
#define AV_LOCAL            0.395 /**< Access Vector Local. */

/**
 * @brief AccessComplexity (AC) Constants.
 */
#define AC_LOW    0.71 /**< Access Complexity Low. */
#define AC_MEDIUM 0.61 /**< Access Complexity Medium. */
#define AC_HIGH   0.35 /**< Access Complexity High. */

/**
 * @brief Authentication (Au) Constants.
 */
#define Au_MULTIPLE_INSTANCES 0.45  /**< Authentication multiple instances. */
#define Au_SINGLE_INSTANCE    0.56  /**< Authentication single instances. */
#define Au_NONE               0.704 /**< No Authentication. */

/**
 * @brief ConfidentialityImpact (C) Constants.
 */
#define C_NONE     0.0   /**< No Confidentiality Impact. */
#define C_PARTIAL  0.275 /**< Partial Confidentiality Impact. */
#define C_COMPLETE 0.660 /**< Complete Confidentiality Impact. */

/**
 * @brief IntegrityImpact (I) Constants.
 */
#define I_NONE     0.0   /**< No Integrity Impact. */
#define I_PARTIAL  0.275 /**< Partial Integrity Impact. */
#define I_COMPLETE 0.660 /**< Complete Integrity Impact. */

/**
 * @brief AvailabilityImpact (A) Constants.
 */
#define A_NONE     0.0   /**< No Availability Impact. */
#define A_PARTIAL  0.275 /**< Partial Availability Impact. */
#define A_COMPLETE 0.660 /**< Complete Availability Impact. */
// clang-format on

/**
 * @brief Base metrics.
 */
enum base_metrics
{
  A,  /**< Availability Impact. */
  I,  /**< Integrity Impact. */
  C,  /**< Confidentiality Impact. */
  Au, /**< Authentication. */
  AC, /**< Access Complexity. */
  AV  /**< Access Vector. */
};

/**
 * @brief Describe a CVSS impact element.
 */
struct impact_item
{
  const char *name; /**< Impact element name */
  double nvalue;    /**< Numerical value */
};

/**
 * @brief Describe a CVSS metrics.
 */
struct cvss
{
  double conf_impact;       /**< Confidentiality impact. */
  double integ_impact;      /**< Integrity impact. */
  double avail_impact;      /**< Availability impact. */
  double access_vector;     /**< Access vector. */
  double access_complexity; /**< Access complexity. */
  double authentication;    /**< Authentication. */
};

static const struct impact_item impact_map[][3] = {
  [A] =
    {
      {"N", A_NONE},
      {"P", A_PARTIAL},
      {"C", A_COMPLETE},
    },
  [I] =
    {
      {"N", I_NONE},
      {"P", I_PARTIAL},
      {"C", I_COMPLETE},
    },
  [C] =
    {
      {"N", C_NONE},
      {"P", C_PARTIAL},
      {"C", C_COMPLETE},
    },
  [Au] =
    {
      {"N", Au_NONE},
      {"M", Au_MULTIPLE_INSTANCES},
      {"S", Au_SINGLE_INSTANCE},
    },
  [AV] =
    {
      {"N", AV_NETWORK},
      {"A", AV_ADJACENT_NETWORK},
      {"L", AV_LOCAL},
    },
  [AC] =
    {
      {"L", AC_LOW},
      {"M", AC_MEDIUM},
      {"H", AC_HIGH},
    },
};

/**
 * @brief Determine base metric enumeration from a string.
 *
 * @param[in]  str Base metric in string form, for example "A".
 * @param[out] res Where to write the desired value.
 *
 * @return 0 on success, -1 on error.
 */
static int
toenum (const char *str, enum base_metrics *res)
{
  int rc = 0; /* let's be optimistic */

  if (g_strcmp0 (str, "A") == 0)
    *res = A;
  else if (g_strcmp0 (str, "I") == 0)
    *res = I;
  else if (g_strcmp0 (str, "C") == 0)
    *res = C;
  else if (g_strcmp0 (str, "Au") == 0)
    *res = Au;
  else if (g_strcmp0 (str, "AU") == 0)
    *res = Au;
  else if (g_strcmp0 (str, "AV") == 0)
    *res = AV;
  else if (g_strcmp0 (str, "AC") == 0)
    *res = AC;
  else
    rc = -1;

  return rc;
}

/**
 * @brief Calculate Impact Sub Score.
 *
 * @param[in] cvss  Contains the subscores associated
 *            to the metrics.
 *
 * @return The resulting subscore.
 */
static double
get_impact_subscore (const struct cvss *cvss)
{
  return 10.41
         * (1
            - (1 - cvss->conf_impact) * (1 - cvss->integ_impact)
                * (1 - cvss->avail_impact));
}

/**
 * @brief Calculate Exploitability Sub Score.
 *
 * @param[in] cvss  Contains the subscores associated
 *            to the metrics.
 *
 * @return The resulting subscore.
 */
static double
get_exploitability_subscore (const struct cvss *cvss)
{
  return 20 * cvss->access_vector * cvss->access_complexity
         * cvss->authentication;
}

/**
 * @brief  Set impact score from string representation.
 *
 * @param[in] value  The literal value associated to the metric.
 * @param[in] metric The enumeration constant identifying the metric.
 * @param[out] cvss  The structure to update with the score.
 *
 * @return 0 on success, -1 on error.
 */
static inline int
set_impact_from_str (const char *value, enum base_metrics metric,
                     struct cvss *cvss)
{
  int i;

  for (i = 0; i < 3; i++)
    {
      const struct impact_item *impact;

      impact = &impact_map[metric][i];

      if (g_strcmp0 (impact->name, value) == 0)
        {
          switch (metric)
            {
            case A:
              cvss->avail_impact = impact->nvalue;
              break;

            case I:
              cvss->integ_impact = impact->nvalue;
              break;

            case C:
              cvss->conf_impact = impact->nvalue;
              break;

            case Au:
              cvss->authentication = impact->nvalue;
              break;

            case AV:
              cvss->access_vector = impact->nvalue;
              break;

            case AC:
              cvss->access_complexity = impact->nvalue;
              break;

            default:
              return -1;
            }
          return 0;
        }
    }
  return -1;
}

/**
 * @brief Final CVSS score computation helper.
 *
 * @param[in] cvss  The CVSS structure that contains the
 *                  different metrics and associated scores.
 *
 * @return the CVSS score, as a double.
 */
static double
__get_cvss_score (struct cvss *cvss)
{
  double impact = 1.176;
  double impact_sub;
  double exploitability_sub;

  impact_sub = get_impact_subscore (cvss);
  exploitability_sub = get_exploitability_subscore (cvss);

  if (impact_sub < 0.1)
    impact = 0.0;

  return (((0.6 * impact_sub) + (0.4 * exploitability_sub) - 1.5) * impact)
         + 0.0;
}


/**
 * @brief Calculate CVSS Score.
 *
 * @param cvss_str Base vector string from which to compute score.
 *
 * @return The resulting score. -1 upon error during parsing.
 */
double
get_cvss_score_from_base_metrics (const char *cvss_str)
{
  struct cvss cvss;
  char *token, *base_str, *base_metrics;

  if (cvss_str == NULL)
    return -1.0;

  if (g_str_has_prefix (cvss_str, "CVSS:3.1/"))
    return get_cvss_score_from_base_metrics_v3 (cvss_str
                                                + strlen ("CVSS:3.1/"));

  memset (&cvss, 0x00, sizeof (struct cvss));

  base_str = base_metrics = g_strdup_printf ("%s/", cvss_str);

  while ((token = strchr (base_metrics, '/')) != NULL)
    {
      char *token2 = strtok (base_metrics, ":");
      char *metric_name = token2;
      char *metric_value;
      enum base_metrics mval;
      int rc;

      *token++ = '\0';

      if (metric_name == NULL)
        goto ret_err;

      metric_value = strtok (NULL, ":");

      if (metric_value == NULL)
        goto ret_err;

      rc = toenum (metric_name, &mval);
      if (rc)
        goto ret_err;

      if (set_impact_from_str (metric_value, mval, &cvss))
        goto ret_err;

      base_metrics = token;
    }

  g_free (base_str);
  return __get_cvss_score (&cvss);

ret_err:
  g_free (base_str);
  return (double) -1;
}

/* CVSS v3. */

/**
 * @brief Round final score as in spec.
 *
 * @param cvss  CVSS score.
 *
 * @return Rounded score.
 */
static double
roundup (double cvss)
{
  int trim;

  /* "Roundup returns the smallest number, specified to 1 decimal place,
   *  that is equal to or higher than its input. For example, Roundup (4.02)
   *  returns 4.1; and Roundup (4.00) returns 4.0." */

  /* 3.020000001 => 4.0 */
  /* 3.000000001 => 3.0 */

  trim = round (cvss * 100000);
  if ((trim % 10000) == 0)
    return trim / 100000;
  return (floor (trim / 10000) + 1) / 10.0;
}

/**
 * @brief Get impact.
 *
 * @param  value  Metric value.
 *
 * @return Impact.
 */
static double
v3_impact (const char *value)
{
  if (strcasecmp (value, "N") == 0)
    return 0.0;
  if (strcasecmp (value, "L") == 0)
    return 0.22;
  if (strcasecmp (value, "H") == 0)
    return 0.56;
  return -1.0;
}

/**
 * @brief Calculate CVSS Score.
 *
 * @param cvss_str  Vector from which to compute score, without prefix.
 *
 * @return CVSS score, or -1 on error.
 */
static double
get_cvss_score_from_base_metrics_v3 (const char *cvss_str)
{
  gchar **split, **point;
  int scope_changed;
  double impact_conf, impact_integ, impact_avail;
  double vector, complexity, privilege, user;
  double isc_base, impact, exploitability, base;

  /* https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
   * https://www.first.org/cvss/v3.1/specification-document */

  scope_changed = -1;
  impact_conf = -1.0;
  impact_integ = -1.0;
  impact_avail = -1.0;
  vector = -1.0;
  complexity = -1.0;
  privilege = -1.0;
  user = -1.0;

  /* AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N */

  split = g_strsplit (cvss_str, "/", 0);
  point = split;
  while (*point)
    {
      /* Scope. */
      if (strncasecmp ("S:", *point, 2) == 0)
        {
          if (strcasecmp (*point + 2, "U") == 0)
            scope_changed = 0;
          else if (strcasecmp (*point + 2, "C") == 0)
            scope_changed = 1;
        }

      /* Confidentiality. */
      if (strncasecmp ("C:", *point, 2) == 0)
        impact_conf = v3_impact (*point + 2);

      /* Integrity. */
      if (strncasecmp ("I:", *point, 2) == 0)
        impact_integ = v3_impact (*point + 2);

      /* Availability. */
      if (strncasecmp ("A:", *point, 2) == 0)
        impact_avail = v3_impact (*point + 2);

      /* Attack Vector. */
      if (strncasecmp ("AV:", *point, 3) == 0)
        {
          if (strcasecmp (*point + 3, "N") == 0)
            vector = 0.85;
          else if (strcasecmp (*point + 3, "A") == 0)
            vector = 0.62;
          else if (strcasecmp (*point + 3, "L") == 0)
            vector = 0.55;
          else if (strcasecmp (*point + 3, "P") == 0)
            vector = 0.2;
        }

      /* Attack Complexity. */
      if (strncasecmp ("AC:", *point, 3) == 0)
        {
          if (strcasecmp (*point + 3, "L") == 0)
            complexity = 0.77;
          else if (strcasecmp (*point + 3, "H") == 0)
            complexity = 0.44;
        }

      /* Privileges Required. */
      if (strncasecmp ("PR:", *point, 3) == 0)
        {
          if (strcasecmp (*point + 3, "N") == 0)
            privilege = 0.85;
          else if (strcasecmp (*point + 3, "L") == 0)
            privilege = 0.62;
          else if (strcasecmp (*point + 3, "H") == 0)
            privilege = 0.27;
          else
            privilege = -1.0;
        }

      /* User Interaction. */
      if (strncasecmp ("UI:", *point, 3) == 0)
        {
          if (strcasecmp (*point + 3, "N") == 0)
            user = 0.85;
          else if (strcasecmp (*point + 3, "R") == 0)
            user = 0.62;
        }

      point++;
    }

  g_strfreev (split);

  /* All of the base metrics are required. */

  if (scope_changed == -1 || impact_conf == -1.0 || impact_integ == -1.0
      || impact_avail == -1.0 || vector == -1.0 || complexity == -1.0
      || privilege == -1.0 || user == -1.0)
    return -1.0;

  /* Privileges Required has a special case for S:C. */

  if (scope_changed && privilege == 0.62)
    privilege = 0.68;
  else if (scope_changed && privilege == 0.27)
    privilege = 0.5;

  /* Impact. */

  isc_base = 1 - ((1 - impact_conf) * (1 - impact_integ) * (1 - impact_avail));

  if (scope_changed)
    impact = 7.52 * (isc_base - 0.029) - 3.25 * pow ((isc_base - 0.02), 15);
  else
    impact = 6.42 * isc_base;

  if (impact <= 0)
    return 0.0;

  /* Exploitability. */

  exploitability = 8.22 * vector * complexity * privilege * user;

  /* Final. */

  if (scope_changed)
    base = 1.08 * (impact + exploitability);
  else
    base = impact + exploitability;

  if (base > 10.0)
    return 10.0;

  return roundup (base);
}
