/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for Container Image Scanner communication.
 */

#ifndef _GVM_CONTAINER_IMAGE_SCANNER_H
#define _GVM_CONTAINER_IMAGE_SCANNER_H

#include "../util/jsonpull.h"

#include <glib.h>

/* Target builder */
typedef struct container_image_target container_image_target_t;

typedef struct container_image_credential container_image_credential_t;

container_image_target_t *
container_image_target_new (const gchar *, const gchar *, const gchar *);

void
container_image_target_free (container_image_target_t *);

container_image_credential_t *
container_image_credential_new (const gchar *, const gchar *);

void
container_image_credential_free (container_image_credential_t *);

void
container_image_credential_set_auth_data (container_image_credential_t *,
                                          const gchar *, const gchar *);

void
container_image_target_add_credential (container_image_target_t *,
                                       container_image_credential_t *);

char *
container_image_build_scan_config_json (container_image_target_t *target,
                                        GHashTable *scan_preferences);

#endif
