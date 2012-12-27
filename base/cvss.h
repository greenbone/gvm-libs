/* openvas-libraries/base
 * $Id$
 * Description: CVSS utility functions
 *
 * Authors:
 * Preeti Subramanian
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
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

/**
 * @file cvss.h
 * @brief Protos for CVSS utility functions.
 *
 * This file contains the protos for \ref cvss.c
 */

#ifndef _CVSS_H
#define _CVSS_H

#include <glib.h>

double get_cvss_score_from_base_metrics (const char *);
gchar * cvss_as_str (double);

#endif /* not _CVSS_H */
