/* SPDX-FileCopyrightText: 2017-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Implementation of sentry methods.
 *
 * This file contains all methods needed for sentry. To enable sentry and log
 * log in the sentry server, methods in this file are called.
 *
 */

#ifndef _GVM_BASE_GVM_SENTRY_H
#define _GVM_BASE_GVM_SENTRY_H

#ifdef HAVE_SENTRY
#include <sentry.h>
#endif /* HAVE_SENTRY*/

void
gvm_sentry_init (const char *, const char *);

void
gvm_sentry_log (const char *);

void
gvm_close_sentry (void);

int
gvm_has_sentry_support (void);

#endif /* not _GVM_BASE_GVM_SENTRY_H */
