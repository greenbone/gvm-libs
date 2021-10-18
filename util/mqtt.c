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

/**
 * @file
 * @brief Implementation of API to handle MQTT communication.
 *
 * This file contains all methods to handle MQTT communication.
 *
 * Before communicating via MQTT a handle has to be created and a connection
 * established. This is done by calling mqtt_init(). Mmessages can be
 * published via mqtt_publish() afterwards.
 *
 * mqtt_init() should be called only once at program init.
 * After forking mqtt_reset() has to be called in the child. mqtt_publish() can
 * be used after mqtt_reset(). No additional mqtt_init() is needed. A new
 * connection will be established on first call to publish for the current
 * process.
 *
 * mqtt_publish_single_message() is a convenience function for sending single
 * messages. Do not send repeated messages via this function as a new connection
 * is established every call.
 */

#include "mqtt.h"

#include "uuidutils.h" /* gvm_uuid_make */

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  mqtt"

#define QOS 1
#define TIMEOUT 10000L

typedef struct
{
  void *client;
  char *client_id;
} mqtt_t;

static const char *global_server_uri = NULL;
static mqtt_t *global_mqtt_client = NULL;
static gboolean mqtt_initialized = FALSE;

/**
 * @brief Set the global init status.

 * @param Status Status of initialization.
 */
static void
mqtt_set_initialized_status (gboolean status)
{
  mqtt_initialized = status;
}

/**
 * @brief Get the global init status.
 *
 * @return Initialization status of mqtt handling.
 */
gboolean
mqtt_is_initialized ()
{
  return mqtt_initialized;
}

/**
 * @brief Set the global mqtt server URI.

 * @param server_uri_in Server uri to set.
 */
static void
mqtt_set_global_server_uri (const char *server_uri_in)
{
  global_server_uri = server_uri_in;
}

/**
 * @brief Get global server URI.
 *
 * @return Server URI, NULL if not found.
 */
static const char *
mqtt_get_global_server_uri ()
{
  return global_server_uri;
}

/**
 * @brief
 *
 * @return Get global client.
 */
static mqtt_t *
mqtt_get_global_client ()
{
  return global_mqtt_client;
}

/**
 * @brief Set global client.
 */
static void
mqtt_set_global_client (mqtt_t *mqtt)
{
  global_mqtt_client = mqtt;
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
 * @brief Destroy the MQTTClient client of the mqtt_t
 *
 * @param[in] mqtt mqtt_t handle.
 *
 */
static void
mqtt_client_destroy (mqtt_t *mqtt)
{
  if (mqtt == NULL)
    return;

  MQTTClient client;
  client = (MQTTClient) mqtt->client;

  if (client != NULL)
    {
      MQTTClient_destroy (&client);
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
mqtt_client_data_destroy (mqtt_t **mqtt)
{
  g_free ((*mqtt)->client_id);
  g_free (*mqtt);
  *mqtt = NULL;
}

/**
 * @brief Destroy MQTTClient handle and free mqtt_t.
 */
void
mqtt_reset ()
{
  g_debug ("%s: start", __func__);
  mqtt_t *mqtt = mqtt_get_global_client ();

  if (mqtt == NULL)
    return;

  mqtt_client_destroy (mqtt);
  mqtt_client_data_destroy (&mqtt);

  mqtt_set_global_client (NULL);

  g_debug ("%s: end", __func__);
  return;
}

/**
 * @brief Create a new mqtt client.
 *
 * @param mqtt  mqtt_t
 * @param address address of the broker
 *
 * @return MQTTClient or NULL on error.
 */
static MQTTClient
mqtt_create (mqtt_t *mqtt, const char *address)
{
  MQTTClient client;
  MQTTClient_createOptions create_opts = MQTTClient_createOptions_initializer;
  create_opts.MQTTVersion = MQTTVERSION_5;

  if (mqtt == NULL || mqtt->client_id == NULL)
    return NULL;

  int rc = MQTTClient_createWithOptions (&client, address, mqtt->client_id,
                                         MQTTCLIENT_PERSISTENCE_NONE, NULL,
                                         &create_opts);

  if (rc != MQTTCLIENT_SUCCESS)
    {
      g_warning ("%s: Error creating MQTTClient: %s", __func__,
                 MQTTClient_strerror (rc));
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
static char *
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
 * @brief Set MQTTClient of mqtt_t
 *
 * @return 0 on success, -1 on failure.
 */
static int
mqtt_set_client (mqtt_t *mqtt, MQTTClient client)
{
  if (mqtt == NULL)
    {
      return -1;
    }
  mqtt->client = client;
  return 0;
}

/**
 * @brief Make new client and connect to mqtt broker.
 *
 * @param mqtt  Initialized mqtt_t
 *
 * @return 0 on success, <0 on error.
 */
static int
mqtt_connect (mqtt_t *mqtt, const char *server_uri)
{
  int rc;
  MQTTClient client;
  MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer5;
  MQTTProperties connect_properties = MQTTProperties_initializer;
  MQTTResponse resp;

  if (mqtt == NULL)
    return -1;

  client = mqtt_create (mqtt, server_uri);
  if (!client)
    return -2;

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
      return -3;
    }

  mqtt_set_client (mqtt, client);

  return 0;
}

/**
 * @brief Init MQTT communication
 *
 * @param server_uri  Server URI
 *
 * @return 0 on success, <0 on error.
 */
int
mqtt_init (const char *server_uri)
{
  g_debug ("%s: start", __func__);
  mqtt_t *mqtt = NULL;

  mqtt = g_malloc0 (sizeof (mqtt_t));
  const char *global_server_uri;
  // Set random uuid as client id
  if (mqtt_set_client_id (mqtt) == NULL)
    {
      g_warning ("%s: Could not set client id.", __func__);
      g_free (mqtt);
      mqtt = NULL;
      return -1;
    }
  g_debug ("%s: client id set: %s", __func__, mqtt->client_id);
  global_server_uri = mqtt_get_global_server_uri ();
  if (global_server_uri == NULL)
    mqtt_set_global_server_uri (server_uri);
  mqtt_connect (mqtt, server_uri);

  mqtt_set_global_client (mqtt);
  mqtt_set_initialized_status (TRUE);

  g_debug ("%s: end", __func__);
  return 0;
}

/**
 * @brief Use the provided client to publish message on a topic
 *
 * @param mqtt  mqtt_t
 * @param topic Topic to publish on.
 * @param msg   Message to publish on queue.
 *
 * @return 0 on success, <0 on failure.
 */
int
mqtt_client_publish (mqtt_t *mqtt, const char *topic, const char *msg)
{
  MQTTClient client;
  MQTTClient_message pubmsg = MQTTClient_message_initializer;
  MQTTClient_deliveryToken token;
  MQTTResponse resp;
  int rc;

  client = mqtt->client;
  if (client == NULL)
    {
      return -1;
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
      return -2;
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
 * @brief Publish a message on topic using the global client
 *
 * @param topic topic
 * @param msg   message
 *
 * @return 0 on success, <0 on error.
 */
int
mqtt_publish (const char *topic, const char *msg)
{
  mqtt_t *mqtt = NULL;
  const char *server_uri;
  int rc = 0;

  // init new global client if it was mqtt_reset()
  if ((mqtt_get_global_client ()) == NULL)
    {
      server_uri = mqtt_get_global_server_uri ();
      if (server_uri == NULL)
        {
          g_warning ("%s: mqtt_init() has to be called once at program start "
                     "else the server URI is not set. ",
                     __func__);
          return -1;
        }
      mqtt_init (server_uri);
    }
  mqtt = mqtt_get_global_client ();

  rc = mqtt_client_publish (mqtt, topic, msg);

  return rc;
}

/**
 * @brief Send a single message.
 *
 * This functions creates a mqtt handle, connects, sends the message, closes
 * the connection and destroys the handler.
 * This function should not be chosen for repeated and frequent messaging. Its
 * meant for error messages and the likes emitted by openvas.
 *
 * @param server_uri_in Server URI
 * @param topic         Topic to publish to
 * @param msg           Message to publish
 *
 * @return 0 on success, <0 on failure.
 */
int
mqtt_publish_single_message (const char *server_uri_in, const char *topic,
                             const char *msg)
{
  const char *server_uri;
  mqtt_t *mqtt = NULL;
  int ret = 0;

  // If server_uri is NULL try to get global
  if (server_uri_in == NULL)
    {
      server_uri = mqtt_get_global_server_uri ();
      if (server_uri == NULL)
        {
          g_warning (
            "%s: No server URI provided and no global server URI available.",
            __func__);
          return -1;
        }
    }
  else
    {
      server_uri = server_uri_in;
    }

  mqtt = g_malloc0 (sizeof (mqtt_t));
  // Set random uuid as client id
  if (mqtt_set_client_id (mqtt) == NULL)
    {
      g_warning ("%s: Could not set client id.", __func__);
      g_free (mqtt);
      return -2;
    }
  mqtt_connect (mqtt, server_uri);
  mqtt_client_publish (mqtt, topic, msg);

  mqtt_disconnect (mqtt);
  mqtt_client_destroy (mqtt);
  mqtt_client_data_destroy (&mqtt);

  return ret;
}

/**
 * @brief subscribes to a single topic.
 *
 * mqtt_subscribe_r uses given mqtt_t to subscribe with given qos to given
 * topic.
 *
 * To be able to subscribe to a topic the client needs to be connected to a
 * broker.
 *
 * @param mqtt_t	contains the mqtt client
 * @param qos	quality of service of messages within topic
 * @param topic         Topic to subscribe to
 *
 * @return 0 on success, -1 when given mqtt is not useable, -2 when subscription
 * failed.
 */
int
mqtt_subscribe_r (mqtt_t *mqtt, int qos, const char *topic)
{
  if (mqtt == NULL || mqtt->client == NULL)
    {
      return -1;
    }
  MQTTSubscribe_options opts = MQTTSubscribe_options_initializer;
  MQTTProperties props = MQTTProperties_initializer;
  MQTTResponse resp =
    MQTTClient_subscribe5 (mqtt->client, topic, qos, &opts, &props);
  if (resp.reasonCode != MQTTREASONCODE_GRANTED_QOS_1)
    {
      return -2;
    }
  return 0;
}

/**
 * @brief subscribes to a single topic.
 *
 * mqtt_subscribe uses global mqtt_t to subscribe with global qos to given
 * topic.
 *
 * To be able to subscribe to a topic the client needs to be connected to a
 * broker. To do that call `mqtt_init` before `mqtt_subscribe`.
 *
 *
 * @param topic         Topic to subscribe to
 *
 * @return 0 on success, -1 when mqtt is not initialized, -2 when subscription
 * failed.
 */
int
mqtt_subscribe (const char *topic)
{
  return mqtt_subscribe_r (mqtt_get_global_client (), QOS, topic);
}

/**
 * @brief unsubscribe a single topic.
 *
 * This function unsubscribes given client from a given topic.
 *
 * @param mqtt_t	contains the mqtt client
 * @param topic         Topic to unsubscribe from
 *
 * @return 0 on success, -1 when given mqtt is not useable, -2 when unsubscribe
 * failed.
 */
int
mqtt_unsubscribe_r (mqtt_t *mqtt, const char *topic)
{
  if (mqtt == NULL || mqtt->client == NULL)
    {
      return -1;
    }

  if (MQTTClient_unsubscribe (mqtt->client, topic) != MQTTCLIENT_SUCCESS)
    {
      return -2;
    }

  return 0;
}

/**
 * @brief unsubscribe a single topic.
 *
 * This function unsubscribes global client from a given topic.
 *
 * @param topic         Topic to unsubscribe from
 *
 * @return 0 on success, -1 when given mqtt is not useable, -2 when unsubscribe
 * failed.
 */
int
mqtt_unsubscribe (const char *topic)
{
  return mqtt_unsubscribe_r (mqtt_get_global_client (), topic);
}

/**
 * @brief wait for a given timeout in ms to retrieve any message of subscribed
 * topics
 *
 * This function performs a synchronous receive of incoming messages.
 * Using this function allows a single-threaded client subscriber application to
 * be written. When called, this function blocks until the next message arrives
 * or the specified timeout expires.
 *
 * <b>Important note:</b> The application must free() the memory allocated
 * to the topic and payload when processing is complete.
 * @param mqtt an already created and connected mqtt client.
 * @param[out] topic The address of a pointer to a topic. This function
 * allocates the memory for the topic and returns it to the application
 * by setting <i>topic</i> to point to the topic.
 * @param[out] topic_len The length of the topic.
 * @param[out] payload The address of a pointer to the received message. This
 * function allocates the memory for the payload and returns it to the
 * application by setting <i>payload</i> to point to the received message.
 * The pointer is set to NULL if the timeout expires.
 * @param[out] payload_len The length of the payload.
 * @param timeout The length of time to wait for a message in milliseconds.
 * @return 0 on message retrieved, 1 on no message retrieved and -1 on an error.
 */
int
mqtt_retrieve_message_r (mqtt_t *mqtt, char **topic, int *topic_len,
                         char **payload, int *payload_len,
                         const unsigned int timeout)
{
  int rc = -1;
  char *tmp = NULL;
  MQTTClient_message *message = NULL;
  if (mqtt == NULL || mqtt->client == NULL)
    {
      g_warning ("mqtt is not initialized.");
      goto exit;
    }
  // copy from tmp into topic to make free work as usual and don't force the
  // user to double check topic_len and topic
  rc = MQTTClient_receive (mqtt->client, &tmp, topic_len, &message, timeout);
  if (rc == MQTTCLIENT_SUCCESS || rc == MQTTCLIENT_TOPICNAME_TRUNCATED)
    {
      // successfully checked for new messages but we didn't get any
      if (message)
        {
          g_debug ("%s: got message %s (%d) on topic %s (%d) \n", __func__,
                   (char *) message->payload, message->payloadlen, tmp,
                   *topic_len);

          if ((*topic = calloc (1, *topic_len)) == NULL)
            {
              goto exit;
            }
          rc = 0;
          if ((strncpy (*topic, tmp, *topic_len)) == NULL)
            {
              g_warning ("unable to copy topic");
              rc = -1;
              goto exit;
            }

          *payload_len = message->payloadlen;
          *payload = calloc (1, message->payloadlen);
          if ((strncpy (*payload, (char *) message->payload,
                        message->payloadlen))
              == NULL)
            {
              g_warning ("unable to copy payload");
              rc = -1;
              goto exit;
            }
        }
      else
        {
          rc = 1;
          *payload = NULL;
          *payload_len = 0;
          *topic = NULL;
          *topic_len = 0;
        }
    }
  else
    {
      rc = -1;
    }

exit:
  if (message != NULL)
    MQTTClient_freeMessage (&message);
  if (tmp != NULL)
    MQTTClient_free (tmp);

  return rc;
}

/**
 * @brief wait for a given timeout in ms to retrieve any message of subscribed
 * topics
 *
 * This function performs a synchronous receive of incoming messages.
 * Using this function allows a single-threaded client subscriber application to
 * be written. When called, this function blocks until the next message arrives
 * or the specified timeout expires.
 *
 * <b>Important note:</b> The application must free() the memory allocated
 * to the topic and payload when processing is complete.
 * @param[out] topic The address of a pointer to a topic. This function
 * allocates the memory for the topic and returns it to the application
 * by setting <i>topic</i> to point to the topic.
 * @param[out] topic_len The length of the topic.
 * @param[out] payload The address of a pointer to the received message. This
 * function allocates the memory for the payload and returns it to the
 * application by setting <i>payload</i> to point to the received message.
 * The pointer is set to NULL if the timeout expires.
 * @param[out] payload_len The length of the payload.
 * @param timeout The length of time to wait for a message in milliseconds.
 * @return 0 on message retrieved, 1 on no message retrieved and -1 on an error.
 */
int
mqtt_retrieve_message (char **topic, int *topic_len, char **payload,
                       int *payload_len)
{
  return mqtt_retrieve_message_r (mqtt_get_global_client (), topic, topic_len,
                                  payload, payload_len, 501);
}
