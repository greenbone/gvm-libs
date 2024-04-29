/* SPDX-FileCopyrightText: 2012-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief CVSS utility functions
 *
 * This file contains utility functions for handling CVSS v2 and v3.
 * get_cvss_score_from_base_metrics calculates the CVSS base score from a CVSS
 * base vector.
 *
 * CVSS v3.1:
 *
 * See equations at https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator and
 * constants at https://www.first.org/cvss/v3.1/specification-document (section
 * 7.4. Metric Values).
 *
 * CVSS v3.0:
 *
 * See equations at https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator and
 * constants at https://www.first.org/cvss/v3.0/specification-document (section
 * 8.4. Metric Levels).
 *
 * CVSS v2:
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

#include "cvss.h"

#include <glib.h>
#include <math.h>
#include <strings.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/* Static Headers. */

static double
get_cvss_score_from_base_metrics_v3 (const char *);

static double
get_cvss_score_from_metrics_v4 (const char *);

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
 * @brief CVSS v2 Base metrics.
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

// CVSS 4.0

/**
 * @brief CVSS 4.0 metrics.
 */
typedef enum
{
  // Base (11 metrics)
  CVSS4_AV, /**< Attack Vector */
  CVSS4_AC, /**< Attack Complexity */
  CVSS4_AT, /**< Attack Requirements */
  CVSS4_PR, /**< Privileges Required */
  CVSS4_UI, /**< User Interaction */
  CVSS4_VC, /**< Confidentiality Impact to the Vulnerable System */
  CVSS4_VI, /**< Integrity Impact to the Vulnerable System */
  CVSS4_VA, /**< Availability Impact to the Vulnerable System */
  CVSS4_SC, /**< Confidentiality Impact to the Subsequent System */
  CVSS4_SI, /**< Integrity Impact to the Subsequent System */
  CVSS4_SA, /**< Availability Impact to the Subsequent System */
  // Threat (1 metric)
  CVSS4_E, /**< Exploit Maturity */
  // Environmental (14 metrics)
  CVSS4_CR,  /**< Confidentiality Requirement */
  CVSS4_IR,  /**< Integrity Requirement */
  CVSS4_AR,  /**< Availability Requirement */
  CVSS4_MAV, /**< Modified Attack Vector */
  CVSS4_MAC, /**< Modified Attack Complexity */
  CVSS4_MAT, /**< Modified Attack Requirements */
  CVSS4_MPR, /**< Modified Privileges Required */
  CVSS4_MUI, /**< Modified User Interaction */
  CVSS4_MVC, /**< Modified Confidentiality Impact to the Vulnerable System */
  CVSS4_MVI, /**< Modified Integrity Impact to the Vulnerable System */
  CVSS4_MVA, /**< Modified Availability Impact to the Vulnerable System */
  CVSS4_MSC, /**< Modified Confidentiality Impact to the Subsequent System */
  CVSS4_MSI, /**< Modified Integrity Impact to the Subsequent System */
  CVSS4_MSA, /**< Modified Availability Impact to the Subsequent System */
  // Supplemental (6 metrics)
  CVSS4_S,  /**< Safety */
  CVSS4_AU, /**< Automatable */
  CVSS4_R,  /**< Recovery */
  CVSS4_V,  /**< Value Density */
  CVSS4_RE, /**< Vulnerability Response Effort */
  CVSS4_U,  /**< Provider Urgency */
  // Maximum number
  CVSS4_METRICS_MAX, /**< Maximum number of metrics */
} cvss4_metric_t;

/**
 * @brief Blank simplified CVSS 4.0 metrics string
 */
#define CVSS_METRICS_STR_BLANK "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

/**
 * @brief Blank simplified CVSS 4.0 macrovector string
 */
#define CVSS_MACROVECTOR_BLANK "XXXXXX"

/**
 * @brief String to enum mapping and allowed values for a CVSS 4.0 metric.
 *
 * This assumes all allowed values are single characters.
 * The Provider Urgency metric can be longer, so it needs special handling
 *  only using the first letter.
 */
typedef struct
{
  const char *metric_str;      /**< The metric abbreviation string */
  const cvss4_metric_t metric; /**< The metric enum value */
  const char *values;          /**< String of characters allowed as values */
} cvss4_metric_def_t;

/**
 * @brief String to enum mappings and allowed values for CVSS 4.0 metrics.
 *
 * Notes:
 * - The Provider Urgency metric can be longer than one character,
 *    so it needs special handling.
 * - The orginal specification only lists the value S (Safety) for the
 *    modified metrics MSI and MSA, but the calculator reference implementation
 *    also uses it for the unmodified ones, SI and SA.
 */
static cvss4_metric_def_t cvss4_metric_defs[] = {
  // Base (11 metrics)
  {"AV", CVSS4_AV, "NALP"},
  {"AC", CVSS4_AC, "LH"},
  {"AT", CVSS4_AT, "NP"},
  {"PR", CVSS4_PR, "NLH"},
  {"UI", CVSS4_UI, "NPA"},
  {"VC", CVSS4_VC, "HLN"},
  {"VI", CVSS4_VI, "HLN"},
  {"VA", CVSS4_VA, "HLN"},
  {"SC", CVSS4_SC, "HLN"},
  {"SI", CVSS4_SI, "HLNS"},
  {"SA", CVSS4_SA, "HLNS"},
  // Threat (1 metric)
  {"E", CVSS4_E, "XAPU"},
  // Environmental (14 metrics)
  {"CR", CVSS4_CR, "XHML"},
  {"IR", CVSS4_IR, "XHML"},
  {"AR", CVSS4_AR, "XHML"},
  {"MAV", CVSS4_MAV, "XNALP"},
  {"MAC", CVSS4_MAC, "XLH"},
  {"MAT", CVSS4_MAT, "XNP"},
  {"MPR", CVSS4_MPR, "XNLH"},
  {"MUI", CVSS4_MUI, "XNPA"},
  {"MVC", CVSS4_MVC, "XHLN"},
  {"MVI", CVSS4_MVI, "XHLN"},
  {"MVA", CVSS4_MVA, "XHLN"},
  {"MSC", CVSS4_MSC, "XHLN"},
  {"MSI", CVSS4_MSI, "XHLNS"},
  {"MSA", CVSS4_MSA, "XHLNS"},
  // Supplemental (6 metrics)
  {"S", CVSS4_S, "XNP"},
  {"AU", CVSS4_AU, "XNY"},
  {"R", CVSS4_R, "XAUI"},
  {"V", CVSS4_V, "XDC"},
  {"RE", CVSS4_RE, "XLMH"},
  {"U", CVSS4_U, "XCGAR"}, // Abbreviated to first letters
  // Max number / array terminator
  {NULL, CVSS4_METRICS_MAX, NULL}};

/**
 * @brief Key-Value mappings of CVSS 4.0 macrovectors to scores.
 */
typedef struct
{
  const char *vector;
  double score;
} cvss4_macrovector_mapping_t;

/**
 * @brief CVSS 4.0 macrovector mappings
 *
 * This list has been generated from the lookup table in the
 *  FIRST CVSS calculator reference implementation at
 *  https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js
 */
static const cvss4_macrovector_mapping_t cvss4_macrovector_mappings[] = {
  {"000000", 10},  {"000001", 9.9}, {"000010", 9.8}, {"000011", 9.5},
  {"000020", 9.5}, {"000021", 9.2}, {"000100", 10},  {"000101", 9.6},
  {"000110", 9.3}, {"000111", 8.7}, {"000120", 9.1}, {"000121", 8.1},
  {"000200", 9.3}, {"000201", 9},   {"000210", 8.9}, {"000211", 8},
  {"000220", 8.1}, {"000221", 6.8}, {"001000", 9.8}, {"001001", 9.5},
  {"001010", 9.5}, {"001011", 9.2}, {"001020", 9},   {"001021", 8.4},
  {"001100", 9.3}, {"001101", 9.2}, {"001110", 8.9}, {"001111", 8.1},
  {"001120", 8.1}, {"001121", 6.5}, {"001200", 8.8}, {"001201", 8},
  {"001210", 7.8}, {"001211", 7},   {"001220", 6.9}, {"001221", 4.8},
  {"002001", 9.2}, {"002011", 8.2}, {"002021", 7.2}, {"002101", 7.9},
  {"002111", 6.9}, {"002121", 5},   {"002201", 6.9}, {"002211", 5.5},
  {"002221", 2.7}, {"010000", 9.9}, {"010001", 9.7}, {"010010", 9.5},
  {"010011", 9.2}, {"010020", 9.2}, {"010021", 8.5}, {"010100", 9.5},
  {"010101", 9.1}, {"010110", 9},   {"010111", 8.3}, {"010120", 8.4},
  {"010121", 7.1}, {"010200", 9.2}, {"010201", 8.1}, {"010210", 8.2},
  {"010211", 7.1}, {"010220", 7.2}, {"010221", 5.3}, {"011000", 9.5},
  {"011001", 9.3}, {"011010", 9.2}, {"011011", 8.5}, {"011020", 8.5},
  {"011021", 7.3}, {"011100", 9.2}, {"011101", 8.2}, {"011110", 8},
  {"011111", 7.2}, {"011120", 7},   {"011121", 5.9}, {"011200", 8.4},
  {"011201", 7},   {"011210", 7.1}, {"011211", 5.2}, {"011220", 5},
  {"011221", 3},   {"012001", 8.6}, {"012011", 7.5}, {"012021", 5.2},
  {"012101", 7.1}, {"012111", 5.2}, {"012121", 2.9}, {"012201", 6.3},
  {"012211", 2.9}, {"012221", 1.7}, {"100000", 9.8}, {"100001", 9.5},
  {"100010", 9.4}, {"100011", 8.7}, {"100020", 9.1}, {"100021", 8.1},
  {"100100", 9.4}, {"100101", 8.9}, {"100110", 8.6}, {"100111", 7.4},
  {"100120", 7.7}, {"100121", 6.4}, {"100200", 8.7}, {"100201", 7.5},
  {"100210", 7.4}, {"100211", 6.3}, {"100220", 6.3}, {"100221", 4.9},
  {"101000", 9.4}, {"101001", 8.9}, {"101010", 8.8}, {"101011", 7.7},
  {"101020", 7.6}, {"101021", 6.7}, {"101100", 8.6}, {"101101", 7.6},
  {"101110", 7.4}, {"101111", 5.8}, {"101120", 5.9}, {"101121", 5},
  {"101200", 7.2}, {"101201", 5.7}, {"101210", 5.7}, {"101211", 5.2},
  {"101220", 5.2}, {"101221", 2.5}, {"102001", 8.3}, {"102011", 7},
  {"102021", 5.4}, {"102101", 6.5}, {"102111", 5.8}, {"102121", 2.6},
  {"102201", 5.3}, {"102211", 2.1}, {"102221", 1.3}, {"110000", 9.5},
  {"110001", 9},   {"110010", 8.8}, {"110011", 7.6}, {"110020", 7.6},
  {"110021", 7},   {"110100", 9},   {"110101", 7.7}, {"110110", 7.5},
  {"110111", 6.2}, {"110120", 6.1}, {"110121", 5.3}, {"110200", 7.7},
  {"110201", 6.6}, {"110210", 6.8}, {"110211", 5.9}, {"110220", 5.2},
  {"110221", 3},   {"111000", 8.9}, {"111001", 7.8}, {"111010", 7.6},
  {"111011", 6.7}, {"111020", 6.2}, {"111021", 5.8}, {"111100", 7.4},
  {"111101", 5.9}, {"111110", 5.7}, {"111111", 5.7}, {"111120", 4.7},
  {"111121", 2.3}, {"111200", 6.1}, {"111201", 5.2}, {"111210", 5.7},
  {"111211", 2.9}, {"111220", 2.4}, {"111221", 1.6}, {"112001", 7.1},
  {"112011", 5.9}, {"112021", 3},   {"112101", 5.8}, {"112111", 2.6},
  {"112121", 1.5}, {"112201", 2.3}, {"112211", 1.3}, {"112221", 0.6},
  {"200000", 9.3}, {"200001", 8.7}, {"200010", 8.6}, {"200011", 7.2},
  {"200020", 7.5}, {"200021", 5.8}, {"200100", 8.6}, {"200101", 7.4},
  {"200110", 7.4}, {"200111", 6.1}, {"200120", 5.6}, {"200121", 3.4},
  {"200200", 7},   {"200201", 5.4}, {"200210", 5.2}, {"200211", 4},
  {"200220", 4},   {"200221", 2.2}, {"201000", 8.5}, {"201001", 7.5},
  {"201010", 7.4}, {"201011", 5.5}, {"201020", 6.2}, {"201021", 5.1},
  {"201100", 7.2}, {"201101", 5.7}, {"201110", 5.5}, {"201111", 4.1},
  {"201120", 4.6}, {"201121", 1.9}, {"201200", 5.3}, {"201201", 3.6},
  {"201210", 3.4}, {"201211", 1.9}, {"201220", 1.9}, {"201221", 0.8},
  {"202001", 6.4}, {"202011", 5.1}, {"202021", 2},   {"202101", 4.7},
  {"202111", 2.1}, {"202121", 1.1}, {"202201", 2.4}, {"202211", 0.9},
  {"202221", 0.4}, {"210000", 8.8}, {"210001", 7.5}, {"210010", 7.3},
  {"210011", 5.3}, {"210020", 6},   {"210021", 5},   {"210100", 7.3},
  {"210101", 5.5}, {"210110", 5.9}, {"210111", 4},   {"210120", 4.1},
  {"210121", 2},   {"210200", 5.4}, {"210201", 4.3}, {"210210", 4.5},
  {"210211", 2.2}, {"210220", 2},   {"210221", 1.1}, {"211000", 7.5},
  {"211001", 5.5}, {"211010", 5.8}, {"211011", 4.5}, {"211020", 4},
  {"211021", 2.1}, {"211100", 6.1}, {"211101", 5.1}, {"211110", 4.8},
  {"211111", 1.8}, {"211120", 2},   {"211121", 0.9}, {"211200", 4.6},
  {"211201", 1.8}, {"211210", 1.7}, {"211211", 0.7}, {"211220", 0.8},
  {"211221", 0.2}, {"212001", 5.3}, {"212011", 2.4}, {"212021", 1.4},
  {"212101", 2.4}, {"212111", 1.2}, {"212121", 0.5}, {"212201", 1},
  {"212211", 0.3}, {"212221", 0.1}, {NULL, 0.0}};

/**
 * @brief Hashtable for quick lookup of CVSS macrovector scores.
 *
 * Macrovector scores should be looked up with cvss4_macrovector_score
 *  which ensures the table is initialized and returns the scores as
 *  double values instead of pointers.
 */
static GHashTable *cvss4_macrovector_table = NULL;

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

  if (g_str_has_prefix (cvss_str, "CVSS:3.1/")
      || g_str_has_prefix (cvss_str, "CVSS:3.0/"))
    return get_cvss_score_from_base_metrics_v3 (cvss_str
                                                + strlen ("CVSS:3.X/"));
  if (g_str_has_prefix (cvss_str, "CVSS:4.0/"))
    return get_cvss_score_from_metrics_v4 (cvss_str + strlen ("CVSS:4.X/"));

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

  /* 3.020000000 => 3.1 */
  /* 3.000000001 => 3.0 */
  /* 5.299996    => 5.3 */
  /* 5.500320    => 5.6 */

  trim = round (cvss * 100000);
  if ((trim % 10000) == 0)
    return ((double) trim) / 100000;
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
   * https://www.first.org/cvss/v3.1/specification-document
   * https://www.first.org/cvss/v3.0/specification-document */

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

/**
 * @brief Initialize the CVSS 4.0 macrovector lookup table.
 */
static void
cvss4_init_macrovector_table ()
{
  if (cvss4_macrovector_table)
    return;

  int index = 0;
  cvss4_macrovector_table = g_hash_table_new (g_str_hash, g_str_equal);
  while (cvss4_macrovector_mappings[index].vector != NULL)
    {
      g_hash_table_insert (cvss4_macrovector_table,
                           (gpointer) cvss4_macrovector_mappings[index].vector,
                           (gpointer) &cvss4_macrovector_mappings[index].score);

      index++;
    }
}

/**
 * @brief Get the CVSS 4.0 score for a given macrovector string.
 *
 * @param[in]  vector  The macrovector to look up.
 *
 * @return The score of the given vector or -1.0 if the macrovector is invalid.
 */
static inline double
cvss4_macrovector_score (const char *vector)
{
  double *score_ptr;

  cvss4_init_macrovector_table ();
  score_ptr = g_hash_table_lookup (cvss4_macrovector_table, vector);
  if (score_ptr)
    return *score_ptr;
  return -1.0;
}

/**
 * @brief Get the effective value of a metric in a simplified CVSS4 vector.
 *
 * As this only returns the first character, the Provider Urgency metric
 *  (CVSS4_U) needs special handling to get the full string.
 *
 * @param[in]  simplified_vec  The simplified vector string to get value from.
 * @param[in]  metric          The metric to get the value of.
 *
 * @return The metric value as a single character.
 */
static char
cvss4_m (const char *simplified_vec, cvss4_metric_t metric)
{
  char selected = simplified_vec[metric];

  // If E=X it will default to the worst case i.e. E=A
  if (metric == CVSS4_E && selected == 'X')
    return 'A';

  // If CR=X, IR=X or AR=X they will default to the worst case
  //  i.e. CR=H, IR=H and AR=H
  if ((metric == CVSS4_CR || metric == CVSS4_IR || metric == CVSS4_AR)
      && selected == 'X')
    return 'H';

  // All other environmental metrics just overwrite base score values,
  //  so if they’re not defined just use the base score value.
  if (metric >= CVSS4_AV && metric <= CVSS4_SA)
    {
      char modified_selected = simplified_vec[metric - CVSS4_AV + CVSS4_MAV];
      if (modified_selected != 'X')
        return modified_selected;
    }

  return selected;
}

/**
 * @brief Simplify CVSS 4.0 base vector so metrics can be indexed by enum.
 *
 * The vector is simplified to a strictly ordered character array with
 *  each character index corresponding to the cvss4_base_metrics enum value
 *  and using 'X' for undefined metric values.
 *
 * This relies on all allowed values being single characters, or having
 *  unique first characters in case of the Provider Urgency metric.
 *
 * @param[in]  cvss_str  The original vector without the prefix "CVSS:4.0/".
 *
 * @return A simplified vector string as described above or NULL on error.
 */
static gchar *
simplify_cvss4_vector (const char *cvss_str)
{
  gchar **split_cvss_str, **split_cvss_point;
  gboolean valid = TRUE;
  gchar *vec = NULL;
  cvss4_metric_t metric;

  if (cvss_str == NULL || strcmp (cvss_str, "") == 0)
    return NULL;

  vec = g_strdup (CVSS_METRICS_STR_BLANK);

  split_cvss_str = g_strsplit (cvss_str, "/", -1);
  split_cvss_point = split_cvss_str;
  while (valid && *split_cvss_point)
    {
      if (strcmp (*split_cvss_point, "") == 0)
        {
          split_cvss_point++;
          continue;
        }

      gchar **split_component = g_strsplit (*split_cvss_point, ":", 2);
      const gchar *metric_str = split_component[0], *value = split_component[1];

      valid = FALSE;

      if (value == NULL)
        {
          g_debug ("%s: value for metric %s missing", __func__, metric_str);
          break;
        }
      else if (strcasecmp (metric_str, "U") == 0)
        {
          // Special case for the Provider Urgency metric
          if (strcasecmp (value, "Red") && strcasecmp (value, "Amber")
              && strcasecmp (value, "Green") && strcasecmp (value, "Clear")
              && strcasecmp (value, "X"))
            {
              g_debug ("%s: value for metric %s must be one of"
                       " 'Red', 'Amber', 'Green', 'Clear', 'X'",
                       __func__, metric_str);
              break;
            }
          else
            valid = TRUE;
        }
      else if (strlen (value) != 1)
        {
          g_debug ("%s: value for metric %s must be 1 character", __func__,
                   metric_str);
          break;
        }

      cvss4_metric_def_t *metric_def = &cvss4_metric_defs[0];
      while (metric_def->metric_str)
        {
          if (strcasecmp (metric_str, metric_def->metric_str) == 0)
            {
              char value_char = g_ascii_toupper (value[0]);

              // Reject duplicate metrics
              if (vec[metric_def->metric] != 'X')
                {
                  g_debug ("%s: duplicate metric %s", __func__, metric_str);
                  break;
                }

              // Set the metric in the simplified vector
              if (strchr (metric_def->values, value_char))
                {
                  valid = TRUE;
                  vec[metric_def->metric] = value_char;
                }
              else
                {
                  g_debug ("%s: invalid metric: %s:%c", __func__, metric_str,
                           value_char);
                }
              break;
            }
          metric_def++;
        }

      split_cvss_point++;
      g_strfreev (split_component);
    }
  g_strfreev (split_cvss_str);

  for (metric = CVSS4_AV; valid && metric <= CVSS4_SA; metric++)
    {
      if (vec[metric] == 'X')
        {
          g_debug ("%s: mandatory metric %s is undefined", __func__,
                   cvss4_metric_defs[metric].metric_str);
          valid = FALSE;
        }
    }

  if (!valid)
    {
      g_debug ("%s: vector %s is invalid", __func__, cvss_str);
      g_free (vec);
      return NULL;
    }

  return vec;
}

/**
 * @brief Expands a simplified CVSS 4.0 vector into its full string form
 *
 * @param[in]  vec  The simplified vector to expand
 *
 * @return The full vector, including the "CVSS:4.0/" prefix
 */
static gchar *
cvss4_vector_expand (const char *vec)
{
  cvss4_metric_t metric;
  GString *str = g_string_new ("CVSS:4.0");
  for (metric = 0; metric < CVSS4_METRICS_MAX; metric++)
    {
      const char *expanded_value;
      if (vec[metric] == 'X')
        continue;
      cvss4_metric_def_t def = cvss4_metric_defs[metric];
      if (metric == CVSS4_U)
        {
          switch (vec[metric])
            {
            case 'R':
              expanded_value = "Red";
              break;
            case 'A':
              expanded_value = "Amber";
              break;
            case 'G':
              expanded_value = "Green";
              break;
            case 'C':
              expanded_value = "Clear";
              break;
            default:
              expanded_value = NULL;
            }
        }
      else
        expanded_value = NULL;

      if (expanded_value)
        g_string_append_printf (str, "/%s:%s", def.metric_str, expanded_value);
      else
        g_string_append_printf (str, "/%s:%c", def.metric_str, vec[metric]);
    }
  return g_string_free (str, FALSE);
}

/**
 * @brief Calculate CVSS 4.0 macrovector from a simplified vector.
 *
 * @param[in]  vec  The simplified vector to get the macrovector of
 *
 * @return The macrovector.
 */
static inline gchar *
cvss4_macrovector (const char *vec)
{
  gchar *macrovector;
  if (vec == NULL)
    return NULL;

  macrovector = g_strdup (CVSS_MACROVECTOR_BLANK);

  // EQ1: 0-AV:N and PR:N and UI:N
  //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  //      2-AV:P or not(AV:N or PR:N or UI:N)
  char av = cvss4_m (vec, CVSS4_AV);
  char pr = cvss4_m (vec, CVSS4_PR);
  char ui = cvss4_m (vec, CVSS4_UI);

  if (av == 'N' && pr == 'N' && ui == 'N')
    macrovector[0] = '0';
  else if ((av == 'N' || pr == 'N' || ui == 'N') && !(av == 'P'))
    macrovector[0] = '1';
  else
    macrovector[0] = '2';

  // EQ2: 0-(AC:L and AT:N)
  //      1-(not(AC:L and AT:N))
  char ac = cvss4_m (vec, CVSS4_AC);
  char at = cvss4_m (vec, CVSS4_AT);

  if (ac == 'L' && at == 'N')
    macrovector[1] = '0';
  else
    macrovector[1] = '1';

  // EQ3: 0-(VC:H and VI:H)
  //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
  //      2-not (VC:H or VI:H or VA:H)
  char vc = cvss4_m (vec, CVSS4_VC);
  char vi = cvss4_m (vec, CVSS4_VI);
  char va = cvss4_m (vec, CVSS4_VA);

  if (vc == 'H' && vi == 'H')
    macrovector[2] = '0';
  else if (vc == 'H' || vi == 'H' || va == 'H')
    macrovector[2] = '1';
  else
    macrovector[2] = '2';

  // EQ4: 0-(MSI:S or MSA:S)
  //      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
  //      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)
  //
  // "Effective" SI and SA are the same as MSI and MSA for the purposes of
  //  checking for the "Safety" value.
  char sc = cvss4_m (vec, CVSS4_SI);
  char si = cvss4_m (vec, CVSS4_SI);
  char sa = cvss4_m (vec, CVSS4_SA);
  if (si == 'S' || sa == 'S')
    macrovector[3] = '0';
  else if (sc == 'H' || si == 'H' || sa == 'H')
    macrovector[3] = '1';
  else
    macrovector[3] = '2';

  // EQ5: 0-E:A
  //      1-E:P
  //      2-E:U
  char e = cvss4_m (vec, CVSS4_E);
  if (e == 'A')
    macrovector[4] = '0';
  else if (e == 'P')
    macrovector[4] = '1';
  else
    macrovector[4] = '2';

  // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]
  char cr = cvss4_m (vec, CVSS4_CR);
  char ir = cvss4_m (vec, CVSS4_IR);
  char ar = cvss4_m (vec, CVSS4_AR);
  if ((cr == 'H' && vc == 'H') || (ir == 'H' && vi == 'H')
      || (ar == 'H' && va == 'H'))
    macrovector[5] = '0';
  else
    macrovector[5] = '1';

  return macrovector;
}

/**
 * @brief Calulate the maximal scoring differences from a CVSS 4.0 macrovector.
 *
 * @param[in]  macrovector
 * @param[out] available_distance_eq1     Maximal scoring diff. for EQ1
 * @param[out] available_distance_eq2     Maximal scoring diff. for EQ2
 * @param[out] available_distance_eq3eq6  Maximal scoring diff. for EQ3 and EQ6
 * @param[out] available_distance_eq4     Maximal scoring diff. for EQ4
 * @param[out] available_distance_eq5     Maximal scoring diff. for EQ5
 */
static void
cvss4_maximal_scoring_differences (const char *macrovector,
                                   double *available_distance_eq1,
                                   double *available_distance_eq2,
                                   double *available_distance_eq3eq6,
                                   double *available_distance_eq4,
                                   double *available_distance_eq5)
{
  double value = cvss4_macrovector_score (macrovector);
  double score_eq1_next_lower_macro, score_eq2_next_lower_macro;
  double score_eq3eq6_next_lower_macro;
  double score_eq4_next_lower_macro, score_eq5_next_lower_macro;

  // Next lower macrovector for EQ1 only exists if EQ1 is 0 or 1.
  if (macrovector[0] <= '1')
    {
      gchar *eq1_next_lower_macro = g_strdup (macrovector);
      eq1_next_lower_macro[0]++;
      score_eq1_next_lower_macro =
        cvss4_macrovector_score (eq1_next_lower_macro);
      g_free (eq1_next_lower_macro);
    }
  else
    score_eq1_next_lower_macro = -1.0;

  // Next lower macrovector for EQ2 only exists if EQ2 is 0.
  if (macrovector[1] == '0')
    {
      gchar *eq2_next_lower_macro = g_strdup (macrovector);
      eq2_next_lower_macro[1]++;
      score_eq2_next_lower_macro =
        cvss4_macrovector_score (eq2_next_lower_macro);
    }
  else
    score_eq2_next_lower_macro = -1.0;

  // Next lower macrovector for EQ3.
  if ((macrovector[2] == '0' || macrovector[2] == '1') && macrovector[5] == '1')
    {
      gchar *eq3eq6_next_lower_macro = g_strdup (macrovector);
      eq3eq6_next_lower_macro[2]++;
      score_eq3eq6_next_lower_macro =
        cvss4_macrovector_score (eq3eq6_next_lower_macro);
      g_free (eq3eq6_next_lower_macro);
    }
  else if (macrovector[2] == '1' && macrovector[5] == '0')
    {
      gchar *eq3eq6_next_lower_macro = g_strdup (macrovector);
      eq3eq6_next_lower_macro[5]++;
      score_eq3eq6_next_lower_macro =
        cvss4_macrovector_score (eq3eq6_next_lower_macro);
      g_free (eq3eq6_next_lower_macro);
    }
  else if (macrovector[2] == '0' && macrovector[5] == '0')
    {
      gchar *eq3eq6_next_lower_macro_left = g_strdup (macrovector);
      eq3eq6_next_lower_macro_left[5]++;
      gchar *eq3eq6_next_lower_macro_right = g_strdup (macrovector);
      eq3eq6_next_lower_macro_right[2]++;
      double score_eq3eq6_next_lower_macro_left =
        cvss4_macrovector_score (eq3eq6_next_lower_macro_left);
      double score_eq3eq6_next_lower_macro_right =
        cvss4_macrovector_score (eq3eq6_next_lower_macro_right);

      if (score_eq3eq6_next_lower_macro_left
          > score_eq3eq6_next_lower_macro_right)
        score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left;
      else
        score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right;

      g_free (eq3eq6_next_lower_macro_left);
      g_free (eq3eq6_next_lower_macro_right);
    }
  else
    score_eq3eq6_next_lower_macro = -1.0;

  // Next lower macrovector for EQ4 only exists if EQ4 is 0 or 1.
  if (macrovector[3] <= '1')
    {
      gchar *eq4_next_lower_macro = g_strdup (macrovector);
      eq4_next_lower_macro[3]++;
      score_eq4_next_lower_macro =
        cvss4_macrovector_score (eq4_next_lower_macro);
      g_free (eq4_next_lower_macro);
    }
  else
    score_eq4_next_lower_macro = -1.0;

  // Next lower macrovector for EQ5 only exists if EQ5 is 0 or 1.
  if (macrovector[4] <= '1')
    {
      gchar *eq5_next_lower_macro = g_strdup (macrovector);
      eq5_next_lower_macro[4]++;
      score_eq5_next_lower_macro =
        cvss4_macrovector_score (eq5_next_lower_macro);
      g_free (eq5_next_lower_macro);
    }
  else
    score_eq5_next_lower_macro = -1.0;

  *available_distance_eq1 = score_eq1_next_lower_macro != -1.0
                              ? value - score_eq1_next_lower_macro
                              : -1.0;
  *available_distance_eq2 = score_eq2_next_lower_macro != -1.0
                              ? value - score_eq2_next_lower_macro
                              : -1.0;
  *available_distance_eq3eq6 = score_eq3eq6_next_lower_macro != -1.0
                                 ? value - score_eq3eq6_next_lower_macro
                                 : -1.0;
  *available_distance_eq4 = score_eq4_next_lower_macro != -1.0
                              ? value - score_eq4_next_lower_macro
                              : -1.0;
  *available_distance_eq5 = score_eq5_next_lower_macro != -1.0
                              ? value - score_eq5_next_lower_macro
                              : -1.0;
}

/**
 * @brief Composes a list of max vectors for the given CVSS 4.0 macrovector.
 *
 * @param[in]  macrovector  The macrovector to get the max vectors of.
 *
 * @return NULL-terminated array of vectors in simplified form.
 */
static gchar **
cvss4_max_vectors (const char *macrovector)
{
  const char **eq1_maxes, **eq2_maxes, **eq3eq6_maxes;
  const char *eq4_max, *eq5_max;
  gchar **ret;

  // EQ1
  static const char *eq1_maxes_0[] = {"AV:N/PR:N/UI:N/", NULL};
  static const char *eq1_maxes_1[] = {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/",
                                      "AV:N/PR:N/UI:P/", NULL};
  static const char *eq1_maxes_2[] = {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/",
                                      NULL};
  if (macrovector[0] == '0')
    eq1_maxes = eq1_maxes_0;
  else if (macrovector[0] == '1')
    eq1_maxes = eq1_maxes_1;
  else
    eq1_maxes = eq1_maxes_2;

  // EQ2
  static const char *eq2_maxes_0[] = {"AC:L/AT:N/", NULL};
  static const char *eq2_maxes_1[] = {"AC:H/AT:N/", "AC:L/AT:P/", NULL};
  if (macrovector[1] == '0')
    eq2_maxes = eq2_maxes_0;
  else
    eq2_maxes = eq2_maxes_1;

  // EQ3+EQ6
  static const char *eq3eq6_maxes_00[] = {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/",
                                          NULL};
  static const char *eq3eq6_maxes_01[] = {
    "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/", NULL};
  static const char *eq3eq6_maxes_10[] = {
    "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/", NULL};
  static const char *eq3eq6_maxes_11[] = {
    "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
    "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
    "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/", NULL};
  static const char *eq3eq6_maxes_21[] = {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/",
                                          NULL};
  if ((macrovector[2] == '0'))
    {
      if (macrovector[5] == '0')
        eq3eq6_maxes = eq3eq6_maxes_00;
      else
        eq3eq6_maxes = eq3eq6_maxes_01;
    }
  else if ((macrovector[2] == '1'))
    {
      if (macrovector[5] == '0')
        eq3eq6_maxes = eq3eq6_maxes_10;
      else
        eq3eq6_maxes = eq3eq6_maxes_11;
    }
  else
    eq3eq6_maxes = eq3eq6_maxes_21;

  // EQ4
  if (macrovector[3] == '0')
    eq4_max = "SC:H/SI:S/SA:S/";
  else if (macrovector[3] == '1')
    eq4_max = "SC:H/SI:H/SA:H/";
  else
    eq4_max = "SC:L/SI:L/SA:L/";

  // EQ5
  if (macrovector[4] == '0')
    eq5_max = "E:A/";
  else if (macrovector[4] == '1')
    eq5_max = "E:P/";
  else
    eq5_max = "E:U/";

  GPtrArray *max_vectors = g_ptr_array_new ();
  const char **eq1_max, **eq2_max, **eq3eq6_max;
  for (eq1_max = eq1_maxes; *eq1_max != NULL; eq1_max++)
    {
      for (eq2_max = eq2_maxes; *eq2_max != NULL; eq2_max++)
        {
          for (eq3eq6_max = eq3eq6_maxes; *eq3eq6_max != NULL; eq3eq6_max++)
            {
              gchar *full_vector =
                g_strdup_printf ("%s%s%s%s%s", *eq1_max, *eq2_max, *eq3eq6_max,
                                 eq4_max, eq5_max);
              gchar *vector = simplify_cvss4_vector (full_vector);
              if (vector == NULL)
                g_warning ("%s: generated vector %s is invalid", __func__,
                           full_vector);
              else
                g_ptr_array_add (max_vectors, vector);
              g_free (full_vector);
            }
        }
    }

  g_ptr_array_add (max_vectors, NULL);

  ret = (gchar **) max_vectors->pdata;
  g_ptr_array_free (max_vectors, FALSE);
  return ret;
}

/**
 * @brief Get the index of a CVSS 4.0 metric value for severity distances.
 *
 * @param[in]  metric  The metric to check.
 * @param[in]  value   The value of the given metric.
 *
 * @return The index value
 */
static double
cvss4_metric_level (cvss4_metric_t metric, char value)
{
  switch (metric)
    {
    case CVSS4_AV:
      switch (value)
        {
        case 'N':
          return 0.0;
        case 'A':
          return 0.1;
        case 'L':
          return 0.2;
        case 'P':
          return 0.3;
        default:
          return -99.0;
        }
      break;
    case CVSS4_PR:
      switch (value)
        {
        case 'N':
          return 0.0;
        case 'L':
          return 0.1;
        case 'H':
          return 0.2;
        default:
          return -99.0;
        }
      break;
    case CVSS4_UI:
      switch (value)
        {
        case 'N':
          return 0.0;
        case 'P':
          return 0.1;
        case 'A':
          return 0.2;
        default:
          return -99.0;
        }
      break;
    case CVSS4_AC:
      switch (value)
        {
        case 'L':
          return 0.0;
        case 'H':
          return 0.1;
        default:
          return -99.0;
        }
      break;
    case CVSS4_AT:
      switch (value)
        {
        case 'N':
          return 0.0;
        case 'P':
          return 0.1;
        default:
          return -99.0;
        }
      break;
    case CVSS4_VC:
    case CVSS4_VI:
    case CVSS4_VA:
      switch (value)
        {
        case 'H':
          return 0.0;
        case 'L':
          return 0.1;
        case 'N':
          return 0.2;
        default:
          return -99.0;
        }
      break;
    case CVSS4_SC:
    case CVSS4_SI:
    case CVSS4_SA:
      switch (value)
        {
        case 'S':
          return 0.0;
        case 'H':
          return 0.1;
        case 'L':
          return 0.2;
        case 'N':
          return 0.3;
        default:
          return -99.0;
        }
      break;
    case CVSS4_CR:
    case CVSS4_IR:
    case CVSS4_AR:
      switch (value)
        {
        case 'H':
          return 0.0;
        case 'M':
          return 0.1;
        case 'L':
          return 0.2;
        default:
          return -99.0;
        }
      break;

    // The Exploit Maturity metric is included in the reference implementation
    //  but never used
    /*
    case CVSS4_E:
      switch (value)
      {
        case 'A': return 0.0;
        case 'P': return 0.1;
        case 'U': return 0.2;
      }
      break;
    */
    default:
      return -99.0;
    }
}

/**
 * @brief Calculate severity distance for a metric in two CVSS 4.0 vectors.
 *
 * @param[in]  vec      The vector to be scored in simplified form.
 * @param[in]  max_vec  The max vector to subtract in simplified form.
 *
 * @return The severity distance.
 */
static inline double
cvss4_severity_distance (cvss4_metric_t metric, const char *vec,
                         const char *max_vec)
{
  return cvss4_metric_level (metric, cvss4_m (vec, metric))
         - cvss4_metric_level (metric, max_vec[metric]);
}

/**
 * @brief Calculate current severity distances for given CVSS 4.0 vector
 *
 * @param[in]  vec          The vector in simplified form
 * @param[in]  macrovector  Corresponding macrovector
 * @param[out] current_severity_distance_eq1      Distance for EQ1
 * @param[out] current_severity_distance_eq2      Distance for EQ2
 * @param[out] current_severity_distance_eq3eq6   Distance for EQ3 and EQ6
 * @param[out] current_severity_distance_eq4      Distance for EQ4
 * @param[out] current_severity_distance_eq5      Distance for EQ5
 */
static void
cvss4_current_severity_distances (const char *vec, const char *macrovector,
                                  double *current_severity_distance_eq1,
                                  double *current_severity_distance_eq2,
                                  double *current_severity_distance_eq3eq6,
                                  double *current_severity_distance_eq4,
                                  double *current_severity_distance_eq5)
{
  double severity_distance_AV, severity_distance_PR, severity_distance_UI;
  double severity_distance_AC, severity_distance_AT;
  double severity_distance_VC, severity_distance_VI, severity_distance_VA;
  double severity_distance_SC, severity_distance_SI, severity_distance_SA;
  double severity_distance_CR, severity_distance_IR, severity_distance_AR;

  char **max_vectors, **max_vec;
  max_vectors = cvss4_max_vectors (macrovector);
  for (max_vec = max_vectors; *max_vec != NULL; max_vec++)
    {
      severity_distance_AV = cvss4_severity_distance (CVSS4_AV, vec, *max_vec);
      severity_distance_PR = cvss4_severity_distance (CVSS4_PR, vec, *max_vec);
      severity_distance_UI = cvss4_severity_distance (CVSS4_UI, vec, *max_vec);

      severity_distance_AC = cvss4_severity_distance (CVSS4_AC, vec, *max_vec);
      severity_distance_AT = cvss4_severity_distance (CVSS4_AT, vec, *max_vec);

      severity_distance_VC = cvss4_severity_distance (CVSS4_VC, vec, *max_vec);
      severity_distance_VI = cvss4_severity_distance (CVSS4_VI, vec, *max_vec);
      severity_distance_VA = cvss4_severity_distance (CVSS4_VA, vec, *max_vec);

      severity_distance_SC = cvss4_severity_distance (CVSS4_SC, vec, *max_vec);
      severity_distance_SI = cvss4_severity_distance (CVSS4_SI, vec, *max_vec);
      severity_distance_SA = cvss4_severity_distance (CVSS4_SA, vec, *max_vec);

      severity_distance_CR = cvss4_severity_distance (CVSS4_CR, vec, *max_vec);
      severity_distance_IR = cvss4_severity_distance (CVSS4_IR, vec, *max_vec);
      severity_distance_AR = cvss4_severity_distance (CVSS4_AR, vec, *max_vec);

      if (severity_distance_AV < 0.0 || severity_distance_PR < 0.0
          || severity_distance_UI < 0.0 || severity_distance_AC < 0.0
          || severity_distance_AT < 0.0 || severity_distance_VC < 0.0
          || severity_distance_VI < 0.0 || severity_distance_VA < 0.0
          || severity_distance_SC < 0.0 || severity_distance_SI < 0.0
          || severity_distance_SA < 0.0 || severity_distance_CR < 0.0
          || severity_distance_IR < 0.0 || severity_distance_AR < 0.0)
        continue;

      g_debug ("%s AV:%0.1f PR:%0.1f UI:%0.1f |"
               " AC:%0.1f AT:%0.1f |"
               " VC:%0.1f VI:%0.1f VA:%0.1f |"
               " SC:%0.1f SI:%0.1f SA:%0.1f |"
               " CR:%0.1f IR:%0.1f AR:%0.1f",
               __func__, severity_distance_AV, severity_distance_PR,
               severity_distance_UI, severity_distance_AC, severity_distance_AT,
               severity_distance_VC, severity_distance_VI, severity_distance_VA,
               severity_distance_SC, severity_distance_SI, severity_distance_SA,
               severity_distance_CR, severity_distance_IR,
               severity_distance_AR);
      break;
    }

  gchar *max_vec_expanded = cvss4_vector_expand (*max_vec);
  g_debug ("%s: max_vec: %s", __func__, max_vec_expanded);
  g_free (max_vec_expanded);

  *current_severity_distance_eq1 =
    severity_distance_AV + severity_distance_PR + severity_distance_UI;
  *current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT;
  *current_severity_distance_eq3eq6 =
    severity_distance_VC + severity_distance_VI + severity_distance_VA
    + severity_distance_CR + severity_distance_IR + severity_distance_AR;
  *current_severity_distance_eq4 =
    severity_distance_SC + severity_distance_SI + severity_distance_SA;
  *current_severity_distance_eq5 = 0.0;
}

/**
 * @brief Get the max severity values for a CVSS 4.0 macrovector
 *
 * The values are the MaxSeverity values already multiplied by 0.1
 *
 * @param[in]  macrovector  The macrovector to get the max severity values for
 * @param[out] max_severity_eq1     Max severity for EQ1
 * @param[out] max_severity_eq2     Max severity for EQ2
 * @param[out] max_severity_eq3eq6  Max severity for EQ3 and EQ6
 * @param[out] max_severity_eq4     Max severity for EQ4
 */
static void
cvss4_max_severities (const char *macrovector, double *max_severity_eq1,
                      double *max_severity_eq2, double *max_severity_eq3eq6,
                      double *max_severity_eq4)
{
  switch (macrovector[0])
    {
    case '0':
      *max_severity_eq1 = 0.1;
      break;
    case '1':
      *max_severity_eq1 = 0.4;
      break;
    case '2':
      *max_severity_eq1 = 0.5;
      break;
    default:
      *max_severity_eq1 = -99.0;
    }

  switch (macrovector[1])
    {
    case '0':
      *max_severity_eq2 = 0.1;
      break;
    case '1':
      *max_severity_eq2 = 0.2;
      break;
    default:
      *max_severity_eq2 = -99.0;
    }

  switch (macrovector[2])
    {
    case '0':
      if (macrovector[5] == '0')
        *max_severity_eq3eq6 = 0.7;
      else
        *max_severity_eq3eq6 = 0.6;
      break;
    case '1':
      *max_severity_eq3eq6 = 0.8;
      break;
    case '2':
      *max_severity_eq3eq6 = 1.0;
      break;
    default:
      *max_severity_eq3eq6 = -99.0;
    }

  switch (macrovector[3])
    {
    case '0':
      *max_severity_eq4 = 0.6;
      break;
    case '1':
      *max_severity_eq4 = 0.5;
      break;
    case '2':
      *max_severity_eq4 = 0.4;
      break;
    default:
      *max_severity_eq4 = -99.0;
    }
}

/**
 * @brief Calculate CVSS 4.0 Score.
 *
 * @param cvss_str  Vector from which to compute score, without prefix.
 *
 * @return CVSS score, or -1 on error.
 */
static double
get_cvss_score_from_metrics_v4 (const char *cvss_str)
{
  char *vec = NULL;
  char *macrovector = NULL;

  double available_distance_eq1, available_distance_eq2;
  double available_distance_eq3eq6;
  double available_distance_eq4, available_distance_eq5;

  double current_severity_distance_eq1, current_severity_distance_eq2;
  double current_severity_distance_eq3eq6;
  double current_severity_distance_eq4, current_severity_distance_eq5;

  double max_severity_eq1, max_severity_eq2, max_severity_eq3eq6;
  double max_severity_eq4;

  double mean_distance, value;

  int n_existing_lower = 0;

  // Convert vector to simplified, enum-indexed string
  g_debug ("%s: CVSS string: %s", __func__, cvss_str);
  vec = simplify_cvss4_vector (cvss_str);
  g_debug ("%s: simplified vector: %s", __func__, vec);
  if (vec == NULL)
    return -1.0;

  // Calculate macrovector
  macrovector = cvss4_macrovector (vec);
  value = cvss4_macrovector_score (macrovector);
  g_debug ("%s: macrovector: %s, value: %0.1f", __func__, macrovector, value);
  if (macrovector == NULL)
    {
      g_free (vec);
      return -1.0;
    }

  // Calculate maximum distances
  cvss4_maximal_scoring_differences (
    macrovector, &available_distance_eq1, &available_distance_eq2,
    &available_distance_eq3eq6, &available_distance_eq4,
    &available_distance_eq5);
  g_debug ("%s: maximal scoring diffs:"
           " EQ1:%0.1f EQ2:%0.1f EQ3+EQ6:%0.1f EQ5:%0.1f EQ6:%0.1f",
           __func__, available_distance_eq1, available_distance_eq2,
           available_distance_eq3eq6, available_distance_eq4,
           available_distance_eq5);

  // Calculate current severity distances
  cvss4_current_severity_distances (
    vec, macrovector, &current_severity_distance_eq1,
    &current_severity_distance_eq2, &current_severity_distance_eq3eq6,
    &current_severity_distance_eq4, &current_severity_distance_eq5);

  g_debug ("%s: current severity distances:"
           "EQ1:%0.1f EQ2:%0.1f EQ3+EQ6:%0.1f EQ4:%0.1f EQ5:%0.1f",
           __func__, current_severity_distance_eq1,
           current_severity_distance_eq2, current_severity_distance_eq3eq6,
           current_severity_distance_eq4, current_severity_distance_eq5);

  // Get MaxSeverity
  cvss4_max_severities (macrovector, &max_severity_eq1, &max_severity_eq2,
                        &max_severity_eq3eq6, &max_severity_eq4);

  // Calculate mean distances
  mean_distance = 0.0;
  if (available_distance_eq1 >= 0.0)
    {
      n_existing_lower++;
      double percent_to_next_severity =
        (current_severity_distance_eq1) / max_severity_eq1;
      mean_distance += (available_distance_eq1 * percent_to_next_severity);
    }

  if (available_distance_eq2 >= 0.0)
    {
      n_existing_lower++;
      double percent_to_next_severity =
        (current_severity_distance_eq2) / max_severity_eq2;
      mean_distance += (available_distance_eq2 * percent_to_next_severity);
    }

  if (available_distance_eq3eq6 >= 0.0)
    {
      n_existing_lower++;
      double percent_to_next_severity =
        (current_severity_distance_eq3eq6) / max_severity_eq3eq6;
      mean_distance += (available_distance_eq3eq6 * percent_to_next_severity);
    }

  if (available_distance_eq4 >= 0.0)
    {
      n_existing_lower++;
      double percent_to_next_severity =
        (current_severity_distance_eq4) / max_severity_eq4;
      mean_distance += (available_distance_eq4 * percent_to_next_severity);
    }

  if (available_distance_eq5 >= 0.0)
    {
      // For EQ5 the percentage is always 0
      n_existing_lower++;
    }

  mean_distance = mean_distance / n_existing_lower;

  // Get and adjust macrovector score
  value = value - mean_distance;
  if (value < 0.0)
    value = 0.0;
  else if (value > 10.0)
    value = 10.0;

  return round (value * 10.0) / 10.0;
}
