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
 * This file contains utitlity functions for handlung CVSS.
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
 *                        none:              0.0
 *                        partial:           0.275
 *                        complete:          0.660
 * AvailImpact      = case AvailabilityImpact of
 *                       none:              0.0
 *                       partial:           0.275
 *                       complete:          0.660
 */

#include<string.h>
#include<stdio.h>
#include<stdlib.h>

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
 * @brief Determin base metric enumeration from a string.
 *
 * @param str Base metric in string form, for example "A".
 *
 * @return The respective base_metric enumeration for the
 *         string. -1 in case parsing the string failed.
 */
static enum base_metrics
toenum (char * str)
{
  if (strcmp(str,"A") == 0)
    return A;
  else if (strcmp(str,"I") == 0)
    return I;
  else if (strcmp(str,"C") == 0)
    return C;
  else if (strcmp(str,"Au") == 0)
    return Au;
  else if (strcmp(str,"AV") == 0)
    return AV;
  else if (strcmp(str,"AC") == 0)
    return AC;
  return -1;
}

/**
 * @brief Calculate Impact Sub Score.
 *
 * @param conf_impact Confidentially impact.
 *
 * @param integ_impact Integrity impact.
 *
 * @param avail_impact Availability impact.
 *
 * @return The resulting sub score.
 */
static double
get_impact_subscore (double conf_impact, double integ_impact,
                     double avail_impact)
{
  return (10.41 * (1 - (1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact)));
}

/**
 * @brief Calculate Exploitability Sub Score.
 *
 * @param access_vector Value of access vector.
 *
 * @param access_complexity Value of access complexity.
 *
 * @param authentication Value of authentication.
 *
 * @return The resulting sub score.
 */
static double
get_exploitability_subscore (double access_vector, double access_complexity,
                             double authentication)
{
    return (20 * access_vector * access_complexity * authentication);
}

/**
 * @brief Calculate CVSS Score.
 *
 * @param base_metrics Base vector string from which to compute score.
 *
 * @return The resulting score. -1 upon error during parsing.
 */
double
get_cvss_score_from_base_metrics (char * base_metrics)
{
  double conf_impact = 0.0;
  double integ_impact = 0.0;
  double avail_impact = 0.0;
  double access_vector = 0.0;
  double access_complexity = 0.0;
  double authentication = 0.0;
  double impact_subscore = 0.0;
  double exploitability_subscore = 0.0;
 
  if(base_metrics == NULL)
    return 0.0;

  base_metrics = strdup (base_metrics);
  strcat (base_metrics, "/");
  char *token = strchr (base_metrics, '/');

  while (token != NULL)
    {
      char * token2 = strtok (base_metrics, ":");
      char * base_metric = token2;

      *token++ = '\0';

      if (base_metric == NULL)
        return -1;

      char * base_metric_value = strtok (NULL, ":");

      if (base_metric_value == NULL)
        return -1;

      switch (toenum (base_metric))
      {
        case A:
          if (strcmp (base_metric_value, "N") == 0)
            avail_impact = A_NONE;
          else if (strcmp (base_metric_value, "P") == 0)
            avail_impact = A_PARTIAL;
          else if (strcmp (base_metric_value, "C") == 0)
            avail_impact = A_COMPLETE;
          else
            return -1;
          break;
        case I:
          if (strcmp (base_metric_value, "N") == 0)
            integ_impact = I_NONE;
          else if (strcmp (base_metric_value, "P") == 0)
            integ_impact = I_PARTIAL;
          else if (strcmp (base_metric_value, "C") == 0)
            integ_impact = I_COMPLETE;
          else
            return -1;
          break;
        case C:
          if (strcmp (base_metric_value, "N") == 0)
            conf_impact = C_NONE;
          else if (strcmp (base_metric_value, "P") == 0)
            conf_impact = C_PARTIAL;
          else if (strcmp (base_metric_value, "C") == 0)
            conf_impact = C_COMPLETE;
          else
            return -1;
          break;
        case Au:
          if (strcmp (base_metric_value, "N") == 0)
            authentication = Au_NONE;
          else if (strcmp (base_metric_value, "M") == 0)
            authentication = Au_MULTIPLE_INSTANCES;
          else if (strcmp (base_metric_value, "S") == 0)
            authentication = Au_SINGLE_INSTANCE;
          else
            return -1;
          break;
        case AV:
          if (strcmp (base_metric_value, "N") == 0)
            access_vector = AV_NETWORK;
          else if (strcmp (base_metric_value, "A") == 0)
            access_vector = AV_ADJACENT_NETWORK;
          else if (strcmp (base_metric_value, "L") == 0)
            access_vector = AV_LOCAL;
          else
            return -1;
          break;
        case AC:
          if (strcmp (base_metric_value, "L") == 0)
            access_complexity = AC_LOW;
          else if (strcmp (base_metric_value, "M") == 0)
            access_complexity = AC_MEDIUM;
          else if (strcmp (base_metric_value, "H") == 0)
            access_complexity = AC_HIGH;
          else
            return -1;
          break;
        default:
          return -1;
      }
      base_metrics = token;
      token = strchr (base_metrics, '/');
    }
  free(token);
  impact_subscore = get_impact_subscore (conf_impact, integ_impact, avail_impact);
  exploitability_subscore = get_exploitability_subscore (access_vector, access_complexity, authentication);
  double impact = 1.176;
  if (impact_subscore == 0.0)
    impact = 0.0;
  return (((0.6 * impact_subscore) + (0.4 * exploitability_subscore) - 1.5) * impact);
}
