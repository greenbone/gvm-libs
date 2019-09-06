/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file
 * @brief Protos and data structures for NVT Information data sets.
 *
 * This file contains the protos for \ref nvti.c
 */

#ifndef _NVTI_H
#define _NVTI_H

#include <glib.h>

typedef struct nvtpref nvtpref_t;

nvtpref_t *
nvtpref_new (int, gchar *, gchar *, gchar *);

void
nvtpref_free (nvtpref_t *);

gchar *
nvtpref_name (const nvtpref_t *);

gchar *
nvtpref_type (const nvtpref_t *);

gchar *
nvtpref_default (const nvtpref_t *);

int
nvtpref_id (const nvtpref_t *);

/**
 * @brief The structure for a cross reference of a VT.
 */
typedef struct vtref vtref_t;

/**
 * @brief The structure of a information record that corresponds to a NVT.
 */
typedef struct nvti nvti_t;

vtref_t *
vtref_new (const gchar *, const gchar *, const gchar *);
void
vtref_free (vtref_t *);
const gchar *
vtref_type (const vtref_t *);
const gchar *
vtref_id (const vtref_t *);
const gchar *
vtref_text (const vtref_t *);

int
nvti_add_vtref (nvti_t *, vtref_t *);
guint
nvti_vtref_len (const nvti_t *);
vtref_t *
nvti_vtref (const nvti_t *, guint);

nvti_t *
nvti_new (void);
void
nvti_free (nvti_t *);

gchar *
nvti_oid (const nvti_t *);
gchar *
nvti_name (const nvti_t *);
gchar *
nvti_summary (const nvti_t *);
gchar *
nvti_affected (const nvti_t *);
gchar *
nvti_impact (const nvti_t *);
time_t
nvti_creation_time (const nvti_t *);
time_t
nvti_modification_time (const nvti_t *);
gchar *
nvti_insight (const nvti_t *);
gchar *
nvti_refs (const nvti_t *, const gchar *, const char *, guint);
gchar *
nvti_solution (const nvti_t *);
gchar *
nvti_solution_type (const nvti_t *);
gchar *
nvti_tag (const nvti_t *);
gchar *
nvti_cvss_base (const nvti_t *);
gchar *
nvti_dependencies (const nvti_t *);
gchar *
nvti_required_keys (const nvti_t *);
gchar *
nvti_mandatory_keys (const nvti_t *);
gchar *
nvti_excluded_keys (const nvti_t *);
gchar *
nvti_required_ports (const nvti_t *);
gchar *
nvti_required_udp_ports (const nvti_t *);
gchar *
nvti_detection (const nvti_t *);
gchar *
nvti_qod_type (const nvti_t *);
gint
nvti_timeout (const nvti_t *);
gint
nvti_category (const nvti_t *);
gchar *
nvti_family (const nvti_t *);
guint
nvti_pref_len (const nvti_t *);
const nvtpref_t *
nvti_pref (const nvti_t *, guint);

int
nvti_set_oid (nvti_t *, const gchar *);
int
nvti_set_name (nvti_t *, const gchar *);
int
nvti_set_summary (nvti_t *, const gchar *);
int
nvti_set_insight (nvti_t *, const gchar *);
int
nvti_set_affected (nvti_t *, const gchar *);
int
nvti_set_impact (nvti_t *, const gchar *);
int
nvti_set_creation_time (nvti_t *, const time_t);
int
nvti_set_modification_time (nvti_t *, const time_t);
int
nvti_set_solution (nvti_t *, const gchar *);
int
nvti_set_solution_type (nvti_t *, const gchar *);
int
nvti_add_tag (nvti_t *, const gchar *, const gchar *);
int
nvti_set_tag (nvti_t *, const gchar *);
int
nvti_set_cvss_base (nvti_t *, const gchar *);
int
nvti_set_dependencies (nvti_t *, const gchar *);
int
nvti_set_required_keys (nvti_t *, const gchar *);
int
nvti_set_mandatory_keys (nvti_t *, const gchar *);
int
nvti_set_excluded_keys (nvti_t *, const gchar *);
int
nvti_set_required_ports (nvti_t *, const gchar *);
int
nvti_set_required_udp_ports (nvti_t *, const gchar *);
int
nvti_set_detection (nvti_t *, const gchar *);
int
nvti_set_qod_type (nvti_t *, const gchar *);
int
nvti_set_timeout (nvti_t *, const gint);
int
nvti_set_category (nvti_t *, const gint);
int
nvti_set_family (nvti_t *, const gchar *);

int
nvti_add_refs (nvti_t *, const gchar *, const gchar *, const gchar *);
int
nvti_add_required_keys (nvti_t *, const gchar *);
int
nvti_add_mandatory_keys (nvti_t *, const gchar *);
int
nvti_add_excluded_keys (nvti_t *, const gchar *);
int
nvti_add_required_ports (nvti_t *, const gchar *);
int
nvti_add_required_udp_ports (nvti_t *, const gchar *);
int
nvti_add_pref (nvti_t *, nvtpref_t *);

/* Collections of NVT Infos. */

/**
 * @brief A collection of information records corresponding to NVTs.
 */
typedef GHashTable nvtis_t;

nvtis_t *
nvtis_new (void);

void
nvtis_free (nvtis_t *);

void
nvtis_add (nvtis_t *, nvti_t *);

nvti_t *
nvtis_lookup (nvtis_t *, const char *);

#endif /* not _NVTI_H */
