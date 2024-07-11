/* SPDX-FileCopyrightText: 2009-2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Headers for CPE utils.
 */

#ifndef _GVM_CPEUTILS_H
#define _GVM_CPEUTILS_H

#include <glib.h>
#include <stdio.h>

/**
 * @brief XML context.
 *
 * This structure is used to represent the WFN naming of a CPE.
 */
typedef struct
{
  char *part;
  char *vendor;
  char *product;
  char *version;
  char *update;
  char *edition;
  char *sw_edition;
  char *target_sw;
  char *target_hw;
  char *other;
  char *language;
} cpe_struct_t;

char *
uri_cpe_to_fs_cpe (const char *);

char *
fs_cpe_to_uri_cpe (const char *);

void
uri_cpe_to_cpe_struct (const char *, cpe_struct_t *);

char *
cpe_struct_to_uri_cpe (const cpe_struct_t *);

void
fs_cpe_to_cpe_struct (const char *, cpe_struct_t *);

char *
cpe_struct_to_fs_cpe (const cpe_struct_t *);

static char *
get_uri_component (const char *, int);

static char *
decode_uri_component (const char *);

static void
unpack_sixth_uri_component (const char *, cpe_struct_t *);

static char *
get_fs_component (const char *, int);

static char *
unbind_fs_component (char *);

static char *
add_quoting (const char *);

static char *
bind_cpe_component_for_uri (const char *);

static char *
transform_for_uri (const char *);

static char *
pct_encode (char);

static char *
pack_sixth_uri_component (const cpe_struct_t *);

static char *
bind_cpe_component_for_fs (const char *);

static char *
process_quoted_chars (const char *);

void
cpe_struct_init (cpe_struct_t *);

void
cpe_struct_free (cpe_struct_t *);

static void
trim_pct (char *);

static void
get_code (char *, const char *);

static void
str_cpy (char **, const char *, int);

static gboolean
is_alpha_num (char);
#endif
