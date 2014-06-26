/* openvas-libraries/base
 * $Id$
 * Description: CVSS utility functions
 *
 * Authors:
 * Preeti Subramanian
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
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

/**
 * @file cvss.c
 * @brief CVSS utility functions
 *
 * This file contains utility functions for handling CVSS.
 * Namels a calculator for the CVSS base score from a CVSS base
 * vector.
 *
 * The base equation is the foundation of CVSS scoring. The base equation is:
 * BaseScore6 = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)–1.5)*f(Impact))
 * Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
 * Exploitability = 20* AccessVector*AccessComplexity*Authentication
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>


/* AccessVector (AV) Constants */
#define AV_NETWORK          1.0
#define AV_ADJACENT_NETWORK 0.646
#define AV_LOCAL            0.395

/* AccessComplexity (AC) Constants */
#define AC_LOW    0.71
#define AC_MEDIUM 0.61
#define AC_HIGH   0.35

/* Authentication (Au) Constants */
#define Au_MULTIPLE_INSTANCES 0.45
#define Au_SINGLE_INSTANCE    0.56
#define Au_NONE               0.704

/* ConfidentialityImpact (C) Constants */
#define C_NONE     0.0
#define C_PARTIAL  0.275
#define C_COMPLETE 0.660

/* IntegrityImpact (I) Constants */
#define I_NONE     0.0
#define I_PARTIAL  0.275
#define I_COMPLETE 0.660

/* AvailabilityImpact (A) Constants */
#define A_NONE     0.0
#define A_PARTIAL  0.275
#define A_COMPLETE 0.660


enum base_metrics { A, I, C, Au, AC, AV };

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
   [A] = {
       {"N", A_NONE},
       {"P", A_PARTIAL},
       {"C", A_COMPLETE},
   },
   [I] = {
       {"N", I_NONE},
       {"P", I_PARTIAL},
       {"C", I_COMPLETE},
   },
   [C] = {
       {"N", C_NONE},
       {"P", C_PARTIAL},
       {"C", C_COMPLETE},
   },
   [Au] = {
       {"N", Au_NONE},
       {"M", Au_MULTIPLE_INSTANCES},
       {"S", Au_SINGLE_INSTANCE},
   },
   [AV] = {
       {"N", AV_NETWORK},
       {"A", AV_ADJACENT_NETWORK},
       {"L", AV_LOCAL},
   },
   [AC] = {
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
toenum (const char * str, enum base_metrics *res)
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
  return (10.41 * (1 -
                   (1 - cvss->conf_impact) *
                   (1 - cvss->integ_impact) *
                   (1 - cvss->avail_impact)));
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
  return (20 * cvss->access_vector *
          cvss->access_complexity * cvss->authentication);
}

/**
 * @brief  Set impact score from string representation.
 *
 * @param[in] value  The litteral value associated to the metric.
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
 * @param base_metrics Base vector string from which to compute score.
 *
 * @return The resulting score. -1 upon error during parsing.
 */
double
get_cvss_score_from_base_metrics (const char *cvss_str)
{
  struct cvss cvss;
  char *token, *base_str, *base_metrics;

  memset(&cvss, 0x00, sizeof(struct cvss));

  if (cvss_str == NULL)
    return -1.0;

  base_str = base_metrics = g_strdup_printf ("%s/", cvss_str);

  while ((token = strchr (base_metrics, '/')) != NULL)
    {
      char *token2 = strtok (base_metrics, ":");
      char *metric_name = token2;
      char *metric_value;
      enum base_metrics  mval;
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
  return (double)-1;
}
