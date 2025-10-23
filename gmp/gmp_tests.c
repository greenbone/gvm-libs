/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "gmp.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

/* Mock implementations of external functions */

int
__wrap_gvm_server_sendf (gnutls_session_t *session, const char *fmt, ...);
int
__wrap_gvm_server_sendf (gnutls_session_t *session, const char *fmt, ...)
{
  return (int) mock (session, fmt);
}

int
__wrap_gvm_server_sendf_xml (gnutls_session_t *session, const char *fmt, ...);
int
__wrap_gvm_server_sendf_xml (gnutls_session_t *session, const char *fmt, ...)
{
  return (int) mock (session, fmt);
}

int
__wrap_gvm_server_sendf_xml_quiet (gnutls_session_t *session, const char *fmt,
                                   ...);
int
__wrap_gvm_server_sendf_xml_quiet (gnutls_session_t *session, const char *fmt,
                                   ...)
{
  return (int) mock (session, fmt);
}

int
__wrap_read_entity (gnutls_session_t *session, entity_t *entity);
int
__wrap_read_entity (gnutls_session_t *session, entity_t *entity)
{
  int result = (int) mock (session, entity);
  if (result == 0 && entity != NULL)
    {
      *entity = (entity_t) mock ();
    }
  return result;
}

int
__wrap_try_read_entity (gnutls_session_t *session, int timeout,
                        entity_t *entity);
int
__wrap_try_read_entity (gnutls_session_t *session, int timeout,
                        entity_t *entity)
{
  int result = (int) mock (session, timeout, entity);
  if (result == 0 && entity != NULL)
    {
      *entity = (entity_t) mock ();
    }
  return result;
}

int
__wrap_gvm_connection_sendf (gvm_connection_t *connection, const char *fmt,
                             ...);
int
__wrap_gvm_connection_sendf (gvm_connection_t *connection, const char *fmt, ...)
{
  return (int) mock (connection, fmt);
}

int
__wrap_gvm_connection_sendf_xml_quiet (gvm_connection_t *connection,
                                       const char *fmt, ...);
int
__wrap_gvm_connection_sendf_xml_quiet (gvm_connection_t *connection,
                                       const char *fmt, ...)
{
  return (int) mock (connection, fmt);
}

int
__wrap_read_entity_c (gvm_connection_t *connection, entity_t *entity);
int
__wrap_read_entity_c (gvm_connection_t *connection, entity_t *entity)
{
  int result = (int) mock (connection, entity);
  if (result == 0 && entity != NULL)
    {
      *entity = (entity_t) mock ();
    }
  return result;
}

int
__wrap_try_read_entity_c (gvm_connection_t *connection, int timeout,
                          entity_t *entity);
int
__wrap_try_read_entity_c (gvm_connection_t *connection, int timeout,
                          entity_t *entity)
{
  int result = (int) mock (connection, timeout, entity);
  if (result == 0 && entity != NULL)
    {
      *entity = (entity_t) mock ();
    }
  return result;
}

Describe (gmp);
BeforeEach (gmp)
{
}

AfterEach (gmp)
{
}

/* Helper function to create mock entities */
static entity_t
create_mock_entity (const char *name, const char *text)
{
  entity_t entity = g_malloc0 (sizeof (struct entity_s));
  entity->name = g_strdup (name);
  entity->text = g_strdup (text);
  entity->attributes =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  return entity;
}

/* Helper function to add attributes to mock entities */
static void
add_mock_attribute (entity_t entity, const char *name, const char *value)
{
  g_hash_table_insert (entity->attributes, g_strdup (name), g_strdup (value));
}

/* gmp_task_status */

Ensure (gmp, gmp_task_status_returns_correct_string_for_valid_response)
{
  entity_t response = create_mock_entity ("get_tasks_response", "");
  entity_t task = create_mock_entity ("task", "");
  response->entities = g_slist_append (NULL, task);
  entity_t status = create_mock_entity ("status", "Running");
  task->entities = g_slist_append (NULL, status);

  const char *result = gmp_task_status (response);

  assert_that (result, is_not_null);
  assert_that (result, is_equal_to_string ("Running"));

  free_entity (response);
}

Ensure (gmp, gmp_task_status_returns_null_when_no_task)
{
  entity_t response = create_mock_entity ("get_tasks_response", "");

  const char *result = gmp_task_status (response);

  assert_that (result, is_null);

  free_entity (response);
}

Ensure (gmp, gmp_task_status_returns_null_when_no_status)
{
  entity_t response = create_mock_entity ("get_tasks_response", "");
  entity_t task = create_mock_entity ("task", "");
  response->entities = g_slist_append (NULL, task);

  const char *result = gmp_task_status (response);

  assert_that (result, is_null);

  free_entity (response);
}

/* gmp_read_create_response */

Ensure (gmp, gmp_read_create_response_returns_uuid_on_success)
{
  entity_t mock_entity = create_mock_entity ("create_response", "");
  add_mock_attribute (mock_entity, "status", "201");
  add_mock_attribute (mock_entity, "id",
                      "12345678-1234-1234-1234-123456789012");

  expect (__wrap_read_entity, will_return (0));
  expect (__wrap_read_entity, will_return (mock_entity));

  gchar *uuid = NULL;
  int result = gmp_read_create_response (NULL, &uuid);

  assert_that (result, is_equal_to (201));
  assert_that (uuid, is_not_null);
  assert_that (uuid,
               is_equal_to_string ("12345678-1234-1234-1234-123456789012"));

  g_free (uuid);
}

Ensure (gmp, gmp_read_create_response_succeeds_without_uuid_parameter)
{
  entity_t mock_entity = create_mock_entity ("create_response", "");
  add_mock_attribute (mock_entity, "status", "201");
  add_mock_attribute (mock_entity, "id",
                      "12345678-1234-1234-1234-123456789012");

  expect (__wrap_read_entity, will_return (0));
  expect (__wrap_read_entity, will_return (mock_entity));

  int result = gmp_read_create_response (NULL, NULL);

  assert_that (result, is_equal_to (201));
}

Ensure (gmp, gmp_read_create_response_returns_error_when_no_status)
{
  entity_t mock_entity = create_mock_entity ("create_response", "");

  expect (__wrap_read_entity, will_return (0));
  expect (__wrap_read_entity, will_return (mock_entity));

  gchar *uuid = NULL;
  int result = gmp_read_create_response (NULL, &uuid);

  assert_that (result, is_equal_to (-1));
  assert_that (uuid, is_null);
}

Ensure (gmp, gmp_read_create_response_returns_error_on_read_failure)
{
  expect (__wrap_read_entity, will_return (-1));

  gchar *uuid = NULL;
  int result = gmp_read_create_response (NULL, &uuid);

  assert_that (result, is_equal_to (-1));
  assert_that (uuid, is_null);
}

/* gmp_check_response */

Ensure (gmp, gmp_check_response_succeeds_with_valid_response)
{
  entity_t mock_entity = create_mock_entity ("response", "");
  add_mock_attribute (mock_entity, "status", "200");

  expect (__wrap_read_entity, will_return (0));
  expect (__wrap_read_entity, will_return (mock_entity));

  entity_t entity = NULL;
  int result = gmp_check_response (NULL, &entity);

  assert_that (result, is_equal_to (0));
  assert_that (entity, is_not_null);

  free_entity (mock_entity);
}

Ensure (gmp, gmp_check_response_returns_gmp_error_code)
{
  entity_t mock_entity = create_mock_entity ("response", "");
  add_mock_attribute (mock_entity, "status", "400");

  expect (__wrap_read_entity, will_return (0));
  expect (__wrap_read_entity, will_return (mock_entity));

  entity_t entity = NULL;
  int result = gmp_check_response (NULL, &entity);

  assert_that (result, is_equal_to (400));
  assert_that (entity, is_null);
}

Ensure (gmp, gmp_check_response_returns_error_on_read_failure)
{
  expect (__wrap_read_entity, will_return (-1));

  entity_t entity = NULL;
  int result = gmp_check_response (NULL, &entity);

  assert_that (result, is_equal_to (-1));
  assert_that (entity, is_null);
}

Ensure (gmp, gmp_check_response_returns_error_when_no_status)
{
  entity_t mock_entity = create_mock_entity ("response", "");

  expect (__wrap_read_entity, will_return (0));
  expect (__wrap_read_entity, will_return (mock_entity));

  entity_t entity = NULL;
  int result = gmp_check_response (NULL, &entity);

  assert_that (result, is_equal_to (-1));
  assert_that (entity, is_null);
}

/* gmp_ping */

Ensure (gmp, gmp_ping_succeeds_with_valid_response)
{
  expect (__wrap_gvm_server_sendf, will_return (0));

  entity_t mock_entity = create_mock_entity ("get_version_response", "");
  add_mock_attribute (mock_entity, "status", "200");

  expect (__wrap_try_read_entity, will_return (0));
  expect (__wrap_try_read_entity, will_return (mock_entity));

  int result = gmp_ping (NULL, 0);

  assert_that (result, is_equal_to (0));
}

Ensure (gmp, gmp_ping_returns_error_on_send_failure)
{
  expect (__wrap_gvm_server_sendf, will_return (-1));

  int result = gmp_ping (NULL, 0);

  assert_that (result, is_equal_to (-1));
}

Ensure (gmp, gmp_ping_returns_error_on_read_failure)
{
  expect (__wrap_gvm_server_sendf, will_return (0));
  expect (__wrap_try_read_entity, will_return (-1));

  int result = gmp_ping (NULL, 0);

  assert_that (result, is_equal_to (-1));
}

Ensure (gmp, gmp_ping_returns_error_with_invalid_status)
{
  expect (__wrap_gvm_server_sendf, will_return (0));

  entity_t mock_entity = create_mock_entity ("get_version_response", "");
  add_mock_attribute (mock_entity, "status", "500");

  expect (__wrap_try_read_entity, will_return (0));
  expect (__wrap_try_read_entity, will_return (mock_entity));

  int result = gmp_ping (NULL, 0);

  assert_that (result, is_equal_to (-1));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (
    suite, gmp, gmp_task_status_returns_correct_string_for_valid_response);
  add_test_with_context (suite, gmp, gmp_task_status_returns_null_when_no_task);
  add_test_with_context (suite, gmp,
                         gmp_task_status_returns_null_when_no_status);

  add_test_with_context (suite, gmp,
                         gmp_read_create_response_returns_uuid_on_success);
  add_test_with_context (
    suite, gmp, gmp_read_create_response_succeeds_without_uuid_parameter);
  add_test_with_context (suite, gmp,
                         gmp_read_create_response_returns_error_when_no_status);
  add_test_with_context (
    suite, gmp, gmp_read_create_response_returns_error_on_read_failure);

  add_test_with_context (suite, gmp,
                         gmp_check_response_succeeds_with_valid_response);
  add_test_with_context (suite, gmp, gmp_check_response_returns_gmp_error_code);
  add_test_with_context (suite, gmp,
                         gmp_check_response_returns_error_on_read_failure);
  add_test_with_context (suite, gmp,
                         gmp_check_response_returns_error_when_no_status);

  add_test_with_context (suite, gmp, gmp_ping_succeeds_with_valid_response);
  add_test_with_context (suite, gmp, gmp_ping_returns_error_on_send_failure);
  add_test_with_context (suite, gmp, gmp_ping_returns_error_on_read_failure);
  add_test_with_context (suite, gmp,
                         gmp_ping_returns_error_with_invalid_status);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
