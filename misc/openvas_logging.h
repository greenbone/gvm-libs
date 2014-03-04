/* openvas-libraries/misc
 * $Id$
 * Description: Implementation of logging methods for openvas
 *
 * Authors:
 * Laban Mwangi <lmwangi@penguinlabs.co.ke>
 *
 * Copyright:
 * Copyright (C) 2009 PenguinLabs Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

#ifndef _OPENVAS_LOGGING_H
#define _OPENVAS_LOGGING_H

#include <glib.h>
#include <time.h>

GSList *load_log_configuration (gchar *);

void free_log_configuration (GSList *);

gchar *get_time (gchar *);

void openvas_log_silent (const char *, GLogLevelFlags, const char *, gpointer);
void openvas_log_func (const char *, GLogLevelFlags, const char *, gpointer);

void setup_log_handlers (GSList *);

void setup_legacy_log_handler (void (*)(const char *, va_list));
void log_legacy_write (const char *, ...) G_GNUC_PRINTF (1, 2);
void log_legacy_fflush ();

#endif /* not _OPENVAS_LOGGING_H */
