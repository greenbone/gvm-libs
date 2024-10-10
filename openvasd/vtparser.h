/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Simple JSON reader
 */

#ifndef _GVM_JSONUTILS_H
#define _GVM_JSONUTILS_H

#include "../base/nvti.h"
#include "../util/jsonpull.h"

nvti_t *
openvasd_parse_vt (gvm_json_pull_parser_t *, gvm_json_pull_event_t *);

#endif
