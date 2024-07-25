/* SPDX-FileCopyrightText: 2009-2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Headers for version utils.
 */

#ifndef _GVM_CPEUTILS_H
#define _GVM_CPEUTILS_H

#include <glib.h>
#include <stdio.h>

int
cmp_versions (const char *, const char *);

static char *
prepare_version_string (const char *);

static int
get_release_state (const char *, int);

static char *
get_part (const char *, int);

static gboolean
is_text (const char *);

static char *
str_cpy (char *, int);

#endif
