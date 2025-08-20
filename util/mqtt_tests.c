/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mqtt.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

void
MQTTClient_destroy (MQTTClient *client)
{
  (void) client;
}

Describe (mqtt);
BeforeEach (mqtt)
{
}

AfterEach (mqtt)
{
}

/* mqtt_client_destroy */

Ensure (mqtt, mqtt_client_destroy_nulls_client)
{
  MQTTClient client;
  mqtt_t *mqtt;

  mqtt = g_malloc0 (sizeof (*mqtt));
  mqtt_set_client_id (mqtt);
  client = mqtt_create (mqtt, "address");
  mqtt_set_client (mqtt, client);
  assert_that (mqtt->client, is_not_null);

  mqtt_client_destroy (mqtt);
  assert_that (mqtt->client, is_null);

  // Cleanup
  mqtt_client_data_destroy (&mqtt);
  assert_that (mqtt, is_null);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, mqtt, mqtt_client_destroy_nulls_client);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
