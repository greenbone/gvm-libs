/* OpenVAS Libraries
 * $Id$
 * Description: Header for interface to external sources of resource
 *              information.
 *
 * Authors:
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
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

#ifndef RESOURCE_REQUEST_H
#define RESOURCE_REQUEST_H

#include <glib.h>

/** @brief Type of a resource. */
typedef enum
{
  RESOURCE_TYPE_TARGET, ///< Target(s)- Resource Type.
  RESOURCE_TYPE_LAST    ///< No Resource Type.
} resource_type_t;

GSList* resource_request_sources (resource_type_t resource_type);

GSList* resource_request_resource (const gchar* source,
                                   resource_type_t resource_type,
                                   const gchar* username,
                                   const gchar* password);

#endif /* RESOURCE_REQUEST_H */
