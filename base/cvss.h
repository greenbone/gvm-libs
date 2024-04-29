/* SPDX-FileCopyrightText: 2012-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Protos for CVSS utility functions.
 *
 * This file contains the protos for \ref cvss.c
 */

#ifndef _GVM_CVSS_H
#define _GVM_CVSS_H

#include <glib.h>

double
get_cvss_score_from_base_metrics (const char *);

#endif /* not _GVM_CVSS_H */
