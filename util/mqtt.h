/* SPDX-FileCopyrightText: 2021-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Protos for MQTT handling.
 */

#ifndef _GVM_MQTT_H
#define _GVM_MQTT_H

#include <MQTTClient.h>
#include <glib.h>

#define AUTH_MQTT 1

int
mqtt_init (const char *);

int
mqtt_init_auth (const char *, const char *, const char *);

gboolean
mqtt_is_initialized (void);

void
mqtt_reset (void);

int
mqtt_publish (const char *, const char *);

int
mqtt_publish_single_message_auth (const char *, const char *, const char *,
                                  const char *, const char *);

int
mqtt_publish_single_message (const char *, const char *, const char *);

int
mqtt_subscribe (const char *);

int
mqtt_retrieve_message (char **, int *, char **, int *, const unsigned int);

int
mqtt_unsubscribe (const char *);

#endif /* _GVM_MQTT_H */
