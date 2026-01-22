/* SPDX-FileCopyrightText: 2017-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Implementation of logging methods.
 */

#ifndef _GVM_BASE_LOGGING_H
#define _GVM_BASE_LOGGING_H

#include <glib.h> /* for GSList, gchar, GLogLevelFlags, gpointer */

/**
 * @brief for backward compatibility
 *
 */
#define LOG_REFERENCES_AVAILABLE

GSList *
load_log_configuration (gchar *);

void
free_log_configuration (GSList *);

gchar *
get_time (gchar *);

void
gvm_log_silent (const char *, GLogLevelFlags, const char *, gpointer);
void
gvm_log_func (const char *, GLogLevelFlags, const char *, gpointer);

void
log_func_for_gnutls (int, const char *);

int
setup_log_handlers (GSList *);

void
gvm_log_lock (void);

void
gvm_log_unlock (void);

void
set_log_reference (char *);

char *
get_log_reference (void);

void
free_log_reference (void);

void
set_log_tz (const gchar *);

#endif /* not _GVM_BASE_LOGGING_H */
