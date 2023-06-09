/* SPDX-FileCopyrightText: 2010-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Protos and data structures for configuration file management
 *
 * This file contains the protos for \ref settings.c
 */

#ifndef _GVM_SETTINGS_H
#define _GVM_SETTINGS_H

#include <glib.h>

/**
 * @brief Struct holding options for settings taken from a key-value
 *        config file.
 */
typedef struct
{
  gchar *file_name;   /**< Filename containing key-value pairs. */
  gchar *group_name;  /**< Name of the group containing key-value pairs. */
  GKeyFile *key_file; /**< GKeyFile object where the file is load. */
} settings_t;

void
settings_cleanup (settings_t *);

/**
 * @brief Struct holding options to iterate over a GKeyFile.
 */
typedef struct
{
  gchar **keys;        /**< Keys. */
  settings_t settings; /**< Settings structure. */
  gchar **current_key; /**< Pointer to the current key. */
  gchar **last_key;    /**< Pointer to the last keys. */
} settings_iterator_t;

int
init_settings_iterator_from_file (settings_iterator_t *, const gchar *,
                                  const gchar *);
void
cleanup_settings_iterator (settings_iterator_t *);
int
settings_iterator_next (settings_iterator_t *);
const gchar *
settings_iterator_name (settings_iterator_t *);
const gchar *
settings_iterator_value (settings_iterator_t *);

#endif /* not _GVM_SETTINGS_H */
