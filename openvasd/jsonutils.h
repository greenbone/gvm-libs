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

typedef void *jreader_t;
typedef void *jparser_t;

int
gvm_read_jnode (const char *, jparser_t, jreader_t *);

jparser_t
gvm_parse_jnode (void);

void gvm_close_jnode_reader (jreader_t);

void gvm_close_jnode_parser (jparser_t);

int gvm_jnode_count_elements (jreader_t);

nvti_t *gvm_jnode_parse_vt (jreader_t);

#endif
