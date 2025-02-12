/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/**
 * @file
 * @brief Implementation of logging domain handling.
 */

#ifndef _GVM_LOGGING_DOMAIN_H
#define _GVM_LOGGING_DOMAIN_H

#include <glib.h>

typedef struct gvm_logging_domain gvm_logging_domain_t;

gvm_logging_domain_t *
gvm_logging_domain_new (gchar *log_domain);

void
gvm_logging_domain_free (gvm_logging_domain_t *log_domain);

gchar *
gvm_logging_domain_get_log_domain (gvm_logging_domain_t *log_domain);

gchar *
gvm_logging_domain_get_log_file (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_log_file (gvm_logging_domain_t *log_domain,
                                 gchar *log_file);

gchar *
gvm_logging_domain_get_prepend_string (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_prepend_string (gvm_logging_domain_t *log_domain,
                                       gchar *prepend_string);

gchar *
gvm_logging_domain_get_prepend_time_format (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_prepend_time_format (gvm_logging_domain_t *log_domain,
                                            gchar *prepend_time_format);

GLogLevelFlags *
gvm_logging_domain_get_default_level (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_default_level (gvm_logging_domain_t *log_domain,
                                      GLogLevelFlags default_level);

gchar *
gvm_logging_domain_get_syslog_facility (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_syslog_facility (gvm_logging_domain_t *log_domain,
                                        gchar *syslog_facility);

gchar *
gvm_logging_domain_get_syslog_ident (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_syslog_ident (gvm_logging_domain_t *log_domain,
                                     gchar *syslog_ident);

gchar *
gvm_logging_domain_get_prepend_separator (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_prepend_separator (gvm_logging_domain_t *log_domain,
                                          gchar *prepend_separator);

GIOChannel *
gvm_logging_domain_get_log_channel (gvm_logging_domain_t *log_domain);

void
gvm_logging_domain_set_log_channel (gvm_logging_domain_t *log_domain,
                                    GIOChannel *log_channel);

#endif /* _GVM_LOGGING_DOMAIN_H */
