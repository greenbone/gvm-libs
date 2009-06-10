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
 * @brief OpenVASD Logging stores the parameters loaded from a log configuration 
 * file.
 *
 * @return Nothing - void function.
 */

typedef struct {
	/* This struct instance affects this logdomain e.g libnasl */
	gchar *logdomain;
	/* Prepend this string before every message */
	gchar *prependstring;
	/* If the prependstring above has a %t, use this strftime format */
	gchar *prependtimeformat;
	/* Where to log to */
	gchar *logfile;
	/* What severity level to use */
	gint defaultlevel;
	/* Gio Channel - FD holder for logfile */
	GIOChannel *logchannel;
} openvasd_logging;

/* Loads the log configuration file */
GSList *load_log_configuration (gchar * configfile);

/* Frees resources associated with logging directives */
void free_log_configuration(GSList *logdomainlist);

/* Utility function that formats a timestamp */
gchar *gettime(gchar *time_fmt);

/* Actual log handler */
void openvas_log_func(const char *log_domain, GLogLevelFlags log_level, const char *message, gpointer openvaslogconfiglist);

/* Log router. Sets up relationships between log domains and log handlers */
void setup_log_handlers(  GSList *openvaslogconfiglist );
#endif
