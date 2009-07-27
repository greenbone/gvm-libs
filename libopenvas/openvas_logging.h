/* openvas-libraries/libopenvas
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

/**
 * @struct openvasd_logging
 * @brief OpenVASD Logging stores the parameters loaded from a log configuration
 * file.
 */

typedef struct
{
  gchar *logdomain;         ///< Affected logdomain e.g libnasl.
  gchar *prependstring;     ///< Prepend this string before every message.
  gchar *prependtimeformat; ///< If prependstring has %t, format for strftime.
  gchar *logfile;           ///< Where to log to.
  gint defaultlevel;        ///< What severity level to use.
  GIOChannel *logchannel;   ///< Gio Channel - FD holder for logfile.
} openvasd_logging;

GSList *load_log_configuration (gchar * configfile);

void free_log_configuration (GSList * logdomainlist);

gchar *gettime (gchar * time_fmt);

void openvas_log_func (const char *log_domain, GLogLevelFlags log_level,
                       const char *message, gpointer openvaslogconfiglist);

void setup_log_handlers (GSList * openvaslogconfiglist);
#endif
