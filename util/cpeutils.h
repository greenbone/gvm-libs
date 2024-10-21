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
uri_cpe_to_fs_product (const char *);

char *
fs_cpe_to_uri_cpe (const char *);

char *
fs_cpe_to_uri_product (const char *);

void
uri_cpe_to_cpe_struct (const char *, cpe_struct_t *);

char *
cpe_struct_to_uri_cpe (const cpe_struct_t *);

char *
cpe_struct_to_uri_product (const cpe_struct_t *);

char *
get_version_from_uri_cpe (const char *);

void
fs_cpe_to_cpe_struct (const char *, cpe_struct_t *);

char *
cpe_struct_to_fs_cpe (const cpe_struct_t *);

char *
cpe_struct_to_fs_product (const cpe_struct_t *);

void
cpe_struct_init (cpe_struct_t *);

void
cpe_struct_free (cpe_struct_t *);

gboolean
cpe_struct_match (cpe_struct_t *, cpe_struct_t *);

gboolean
cpe_struct_match_tail (cpe_struct_t *, cpe_struct_t *);

enum set_relation
{
  DISJOINT,
  EQUAL,
  SUBSET,
  SUPERSET,
  UNDEFINED
};

#define CPE_COMPONENT_IS_ANY(component) (component[0] == 'A')

#endif
