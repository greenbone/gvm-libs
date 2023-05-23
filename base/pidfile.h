/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief PID-file management.
 */

#ifndef _GVM_PIDFILE_H
#define _GVM_PIDFILE_H

#include <glib.h>

int
pidfile_create (gchar *);
void
pidfile_remove (gchar *);

#endif /* not _GVM_PIDFILE_H */
