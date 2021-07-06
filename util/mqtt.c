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

/** TODO: Remove dependency ../base/prefs.h **/
#include "../base/prefs.h"
#include "uuidutils.h" /* gvm_uuid_make */

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  mqtt"

#define QOS 1
#define TIMEOUT 10000L

/**
 * @brief Get server uri as specified in the openvas conf file.
 *
 * @return Server URI, NULL if not found.
 */
static const char *
mqtt_get_server_uri ()
{
  return prefs_get ("mqtt_server_uri");
}

/**
 * @brief Disconnect from the Broker.
 *
 * @param mqtt  mqtt_t
 *
 * @return  0 on success, -1 on error.
 */
static int
mqtt_disconnect (mqtt_t *mqtt)
{
  int rc;

  rc = MQTTClient_disconnect5 (mqtt->client, 200,
                               MQTTREASONCODE_NORMAL_DISCONNECTION, NULL);
  if (rc != MQTTCLIENT_SUCCESS)
    {
      g_warning ("Failed to disconnect: %s", MQTTClient_strerror (rc));
      return -1;
    }

  return 0;
}

/**
 * @brief Destroy the mqtt client inside mqtt_t struct
 *
 * @param[in] mqtt mqtt_t handle.
 *
 */
static void
mqtt_client_destroy (mqtt_t *mqtt)
{
  MQTTClient client;
  client = (MQTTClient) mqtt->client;

  if (client != NULL)
    {
      MQTTClient_destroy (client);
      client = NULL;
    }

  return;
}
/**
 * @brief Destroy the mqtt_t data.
 *
 * @param mqtt  mqtt_t
 */
static void
mqtt_client_data_destroy (mqtt_t *mqtt)
{
  g_free (mqtt->addr);
  g_free (mqtt->client_id);
  g_free (mqtt);
  mqtt = NULL;
}

/**
 * @brief Destroy mqtt handle and mqtt_t.
 *
 * @param mqtt  mqtt_t
 */
void
mqtt_reset (mqtt_t *mqtt)
{
  mqtt_client_destroy (mqtt);
  mqtt_client_data_destroy (mqtt);
  return;
}

/**
 * @brief Create a new mqtt client.
 *
 * @param mqtt  mqtt_t
 *
 * @return mqtt client or NULL on error.
 */
static MQTTClient
mqtt_create (mqtt_t *mqtt)
{
  MQTTClient client;
  MQTTClient_createOptions create_opts = MQTTClient_createOptions_initializer;
  create_opts.MQTTVersion = MQTTVERSION_5;

  if (mqtt == NULL)
    return NULL;
  if (mqtt->addr == NULL || mqtt->client_id == NULL)
    return NULL;

  int rc = MQTTClient_createWithOptions (&client, mqtt->addr, mqtt->client_id,
                                         MQTTCLIENT_PERSISTENCE_NONE, NULL,
                                         &create_opts);

  if (rc != MQTTCLIENT_SUCCESS)
    {
      MQTTClient_destroy (&client);
      return NULL;
    }
  return client;
}

/**
 * @brief Set a random client ID.
 *
 * @param mqtt mqtt_t
 *
 * @return Client ID which was set, NULL on failure.
 */
char *
mqtt_set_client_id (mqtt_t *mqtt)
{
  if (mqtt == NULL)
    return NULL;

  char *uuid;

  uuid = gvm_uuid_make ();
  mqtt->client_id = uuid;

  return uuid;
}

/**
 * @brief Set Server Addr.
 *
 * @param mqtt        mqtt_T
 * @param server_uri  URI of server. E.g "tcp://127.0.0.1:1883"
 *
 * @return 0 on success, NULL on error.
 */
static void
mqtt_set_server_addr (mqtt_t *mqtt, const char *server_uri)
{
  if (mqtt == NULL)
    {
      g_warning ("%s:Can not set server addr on unitialized mqtt handle.",
                 __func__);
      return;
    }

  mqtt->addr = g_strdup (server_uri);
}

/**
 * @brief Set client handle
 *
 * @param mqtt    mqtt_t
 * @param client  Client to set
 *
 */
static void
mqtt_set_client (mqtt_t *mqtt, MQTTClient client)
{
  if (mqtt == NULL)
    {
      g_warning ("%s: Can not set clien on uninitialized mqtt handle.",
                 __func__);
      return;
    }
  mqtt->client = client;
  return;
}

/**
 * @brief Init mqtt_t
 *
 * @param server_uri  Server URI
 *
 * @return New mqtt_t, NULL on error
 */
mqtt_t *
mqtt_init (const char *server_uri)
{
  mqtt_t *mqtt = NULL;

  mqtt = g_malloc0 (sizeof (mqtt));

  // Set random uuid as client id
  if (mqtt_set_client_id (mqtt) == NULL)
    {
      g_warning ("%s: Could not set client id.", __func__);
      g_free (mqtt);
      return NULL;
    }
  mqtt_set_server_addr (mqtt, server_uri);
  mqtt_set_client (mqtt, NULL);

  return mqtt;
}

/**
 * @brief Make new client and connect to mqtt broker.
 *
 * @param mqtt  Initialized mqtt_t
 *
 * @return mqtt_t handle, NULL on error.
 */
static mqtt_t *
mqtt_connect (mqtt_t *mqtt)
{
  int rc;
  MQTTClient client;
  MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer5;
  MQTTProperties connect_properties = MQTTProperties_initializer;
  MQTTResponse resp;

  if (mqtt == NULL)
    return NULL;
  client = mqtt_create (mqtt);
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
             "%s: mqtt connection error to %s: %s", __func__, mqtt->addr,
             MQTTClient_strerror (rc));
      MQTTResponse_free (resp);
      return NULL;
    }

  mqtt_set_client (mqtt, client);

  return mqtt;
}

/**
 * @brief Publish message on topic.
 *
 * @param mqtt  MQTT handle.
 * @param topic Topic to publish on.
 * @param msg   Message to publish on queue.
 *
 * @return 0 on success, <0 on failure.
 */
int
mqtt_publish (mqtt_t *mqtt, const char *topic, const char *msg)
{
  MQTTClient client;
  MQTTClient_message pubmsg = MQTTClient_message_initializer;
  MQTTClient_deliveryToken token;
  MQTTResponse resp;
  int rc;
  const char *mqtt_server_uri;

  // init mqtt and make new connection
  if (mqtt == NULL)
    {
      mqtt_server_uri = mqtt_get_server_uri ();
      if (mqtt_server_uri)
        mqtt = mqtt_init (mqtt_server_uri);
      if (mqtt == NULL)
        return -1;
      mqtt = mqtt_connect (mqtt);
      if (mqtt == NULL)
        return -2;
    }

  client = mqtt->client;
  if (client == NULL)
    {
      return -3;
    }

  pubmsg.payload = (char *) msg;
  pubmsg.payloadlen = (int) strlen (msg);
  pubmsg.qos = QOS;
  pubmsg.retained = 0;

  resp = MQTTClient_publishMessage5 (client, topic, &pubmsg, &token);
  rc = resp.reasonCode;
  if (rc != MQTTCLIENT_SUCCESS)
    {
      g_warning ("Failed to connect: %s", MQTTClient_strerror (rc));
      MQTTResponse_free (resp);
      return -4;
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

/**
 * @brief Send a single message.
 *
 * This functions creates a mqtt handle, connects, sends the message, closes
 * the connection and destroys the handler.
 * This function should not be chosen for repeated and frequent messaging. Its
 * meant for Error messages and the likes emitted by openvas.
 *
 * @param topic Topic to publish to
 * @param msg   Message to publish
 *
 * @return 0 on success, <0 on failure.
 */
int
mqtt_publish_single_message (const char *topic, const char *msg)
{
  const char *mqtt_server_uri;
  mqtt_t *mqtt = NULL;

  mqtt_server_uri = mqtt_get_server_uri ();
  if (mqtt_server_uri)
    mqtt = mqtt_init (mqtt_server_uri);
  if (mqtt == NULL)
    return -1;
  mqtt = mqtt_connect (mqtt);
  if (mqtt == NULL)
    {
      mqtt_reset (mqtt);
      return -2;
    }
  if (mqtt_publish (mqtt, topic, msg) != 0)
    {
      mqtt_disconnect (mqtt);
      mqtt_reset (mqtt);
      return -3;
    }
  if (mqtt_disconnect (mqtt) != 0)
    {
      mqtt_reset (mqtt);
      return -4;
    }
  mqtt_reset (mqtt);

  return 0;
}
