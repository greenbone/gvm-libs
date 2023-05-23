/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Array utilities.
 */

#ifndef _GVM_ARRAY_H
#define _GVM_ARRAY_H

#include <glib.h>

typedef GPtrArray array_t;

GPtrArray *
make_array (void);

void
array_reset (array_t **array);

void
array_free (GPtrArray *array);

void
array_add (array_t *array, gpointer pointer);

void
array_terminate (array_t *array);

#endif /* not _GVM_ARRAY_H */
