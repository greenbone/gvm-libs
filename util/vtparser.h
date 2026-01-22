/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Simple JSON reader.
 */

#ifndef _GVM_UTIL_VTPARSER_H
#define _GVM_UTIL_VTPARSER_H

#define _GNU_SOURCE /* See feature_test_macros(7) */
#define _FILE_OFFSET_BITS 64
#include "../base/cvss.h"
#include "../base/nvti.h" /* for nvti_t */
#include "../util/jsonpull.h"

#include <cjson/cJSON.h>
#include <glib.h>
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

int
parse_vt_json (gvm_json_pull_parser_t *, gvm_json_pull_event_t *, nvti_t **);

#endif /* not _GVM_UTIL_VTPARSER_H */