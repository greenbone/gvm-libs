/* Copyright (C) 2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#ifndef _GVM_MQTT_H
#define _GVM_MQTT_H

#ifdef HAVE_MQTT
#include <MQTTClient.h>
#endif /* HAVE_MQTT*/

typedef struct
{
  void *client;
  char *client_id;
  char *addr;
} mqtt_t;

int
gvm_has_mqtt_support (void);

mqtt_t *
mqtt_connect (const char *);

int
mqtt_publish (mqtt_t *, const char *, const char *);

#endif /* _GVM_MQTT_H */
