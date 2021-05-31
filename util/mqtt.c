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

#include "mqtt.h"

#include "uuidutils.h" /* gvm_uuid_make */

#include <glib.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  mqtt"

#define QOS 1
#define TIMEOUT 10000L

/**
 * @brief Check for MQTT support
 *
 * @return 1 if gvm-libs has been built with mqtt, 0 otherwise.
 */
int
gvm_has_mqtt_support ()
{
#ifdef HAVE_MQTT
  return 1;
#endif /* HAVE_MQTT */
  return 0;
}

/**
 * Create a new mqtt client.
 *
 * @param server_uri  URI of server.
 *
 * @return mqtt client
 */
static MQTTClient
mqtt_create (const char *server_uri, char *id)
{
  MQTTClient client;
  MQTTClient_createOptions create_opts = MQTTClient_createOptions_initializer;
  create_opts.MQTTVersion = MQTTVERSION_5;

  int rc = MQTTClient_createWithOptions (
    &client, server_uri, id, MQTTCLIENT_PERSISTENCE_NONE, NULL, &create_opts);

  if (rc != MQTTCLIENT_SUCCESS)
    {
      MQTTClient_destroy (&client);
      return NULL;
    }
  return client;
}

/**
 * @brief connect to a mqtt broker.
 *
 * @param server_uri  Address of the broker.
 *
 * @return Mqtt handle, NULL on error.
 */
mqtt_t *
mqtt_connect (const char *server_uri)
{
  g_warning ("%s", __func__);
  char *uuid;
  int rc;
  MQTTClient client;
  mqtt_t *mqtt = NULL;
  MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer5;
  MQTTProperties connect_properties = MQTTProperties_initializer;
  MQTTResponse resp = MQTTResponse_initializer;

  uuid = gvm_uuid_make ();
  client = mqtt_create (server_uri, uuid);
  if (!client)
    return NULL;

  conn_opts.keepAliveInterval = 0;
  conn_opts.cleanstart = 1;
  conn_opts.MQTTVersion = MQTTVERSION_5;

  resp = MQTTClient_connect5 (client, &conn_opts, &connect_properties, NULL);
  rc = resp.reasonCode;
  MQTTProperties_free (&connect_properties);
  if (rc != MQTTCLIENT_SUCCESS)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: mqtt connection error to %s: %s", __func__, server_uri,
             MQTTClient_strerror (rc));
      MQTTResponse_free (resp);
      return NULL;
    }

  mqtt = g_malloc0 (sizeof (mqtt));
  mqtt->client = client;
  mqtt->addr = g_strdup (server_uri);
  mqtt->client_id = uuid;

  return mqtt;
}

int
mqtt_publish (mqtt_t *mqtt, const char *topic, const char *msg)
{
  MQTTClient client;
  MQTTClient_message pubmsg = MQTTClient_message_initializer;
  MQTTClient_deliveryToken token;
  MQTTResponse resp = MQTTResponse_initializer;
  int rc;

  client = mqtt->client;
  if (!client)
    return -1;

  pubmsg.payload = (char *) msg;
  pubmsg.payloadlen = (int) strlen (msg);
  pubmsg.qos = QOS;
  pubmsg.retained = 0;

  g_warning ("! publish with client id: %s", mqtt->client_id);
  resp = MQTTClient_publishMessage5 (client, topic, &pubmsg, &token);
  rc = resp.reasonCode;
  if (rc != MQTTCLIENT_SUCCESS)
    {
      g_warning ("Failed to connect: %s", MQTTClient_strerror (rc));
      MQTTResponse_free (resp);
      return -1;
    }

  if ((rc = MQTTClient_waitForCompletion (client, token, TIMEOUT))
      != MQTTCLIENT_SUCCESS)
    {
      g_debug ("Message '%s' with delivery token %d could not be "
               "published on topic %s",
               msg, token, topic);
    }

  return rc;
}