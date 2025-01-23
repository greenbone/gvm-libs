/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _GVM_JSON_H
#define _GVM_JSON_H

#define _GNU_SOURCE

#include <cjson/cJSON.h>
#include <glib.h>

gchar *
gvm_json_string_escape (const char *, gboolean);

double
gvm_json_obj_double (cJSON *, const gchar *);

#endif /* _GVM_JSON_H */
