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

/* Helper function to add parent to mock entity */
static void
add_mock_child (entity_t parent, entity_t child)
{
  parent->entities = g_slist_append (parent->entities, child);
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

Ensure (gmp, gmp_authenticate_info_ext_c_returns_success_and_sets_outputs)
{
  entity_t response = create_mock_entity ("authenticate_response", "");
  add_mock_attribute (response, "status", "200");

  entity_t timezone = create_mock_entity ("timezone", "Europe/Berlin");
  entity_t role = create_mock_entity ("role", "Admin");
  entity_t pw_warning =
    create_mock_entity ("password_warning", "Password is short");
  entity_t token = create_mock_entity ("token", "jwt-token-value");

  add_mock_child (response, timezone);
  add_mock_child (response, role);
  add_mock_child (response, pw_warning);
  add_mock_child (response, token);

  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (response));

  char *out_role = NULL;
  char *out_timezone = NULL;
  char *out_pw_warning = NULL;
  char *out_jwt = NULL;

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";
  opts.role = &out_role;
  opts.timezone = &out_timezone;
  opts.pw_warning = &out_pw_warning;
  opts.jwt_requested = 1;
  opts.jwt = &out_jwt;

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (0));
  assert_that (out_role, is_equal_to_string ("Admin"));
  assert_that (out_timezone, is_equal_to_string ("Europe/Berlin"));
  assert_that (out_pw_warning, is_equal_to_string ("Password is short"));
  assert_that (out_jwt, is_equal_to_string ("jwt-token-value"));

  g_free (out_role);
  g_free (out_timezone);
  g_free (out_pw_warning);
  g_free (out_jwt);
}

Ensure (gmp, gmp_authenticate_info_ext_c_succeeds_without_optional_outputs)
{
  entity_t response = create_mock_entity ("authenticate_response", "");
  add_mock_attribute (response, "status", "200");

  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (response));

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (0));
}

Ensure (gmp, gmp_authenticate_info_ext_c_returns_send_error)
{
  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (-1));

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.username = "admin";
  opts.password = "secret";

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (-1));
}

Ensure (gmp, gmp_authenticate_info_ext_c_returns_timeout_on_try_read_timeout)
{
  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (-4));

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (3));
}

Ensure (gmp, gmp_authenticate_info_ext_c_returns_error_on_read_failure)
{
  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (-1));

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (-1));
}

Ensure (gmp, gmp_authenticate_info_ext_c_returns_error_when_status_empty)
{
  entity_t response = create_mock_entity ("authenticate_response", "");
  add_mock_attribute (response, "status", "");

  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (response));

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (-1));
}

Ensure (gmp, gmp_authenticate_info_ext_c_returns_2_on_auth_failure)
{
  entity_t response = create_mock_entity ("authenticate_response", "");
  add_mock_attribute (response, "status", "400");

  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (response));

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "wrong";

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (2));
}

Ensure (gmp,
        gmp_authenticate_info_ext_c_leaves_jwt_null_when_requested_but_missing)
{
  entity_t response = create_mock_entity ("authenticate_response", "");
  add_mock_attribute (response, "status", "200");

  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (response));

  char *out_jwt = (char *) 0x1;

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";
  opts.jwt_requested = 1;
  opts.jwt = &out_jwt;

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (0));
  assert_that (out_jwt, is_null);
}

Ensure (gmp,
        gmp_authenticate_info_ext_c_leaves_optional_outputs_null_when_absent)
{
  entity_t response = create_mock_entity ("authenticate_response", "");
  add_mock_attribute (response, "status", "200");

  expect (__wrap_gvm_connection_sendf_xml_quiet, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (0));
  expect (__wrap_try_read_entity_c, will_return (response));

  char *out_role = (char *) 0x1;
  char *out_timezone = (char *) 0x1;
  char *out_pw_warning = (char *) 0x1;

  gmp_authenticate_info_opts_t opts = gmp_authenticate_info_opts_defaults;
  opts.timeout = 10;
  opts.username = "admin";
  opts.password = "secret";
  opts.role = &out_role;
  opts.timezone = &out_timezone;
  opts.pw_warning = &out_pw_warning;

  int result = gmp_authenticate_info_ext_c (NULL, opts);

  assert_that (result, is_equal_to (0));
  assert_that (out_role, is_null);
  assert_that (out_timezone, is_null);
  assert_that (out_pw_warning, is_null);
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
  add_test_with_context (
    suite, gmp, gmp_authenticate_info_ext_c_returns_success_and_sets_outputs);
  add_test_with_context (
    suite, gmp, gmp_authenticate_info_ext_c_succeeds_without_optional_outputs);
  add_test_with_context (suite, gmp,
                         gmp_authenticate_info_ext_c_returns_send_error);
  add_test_with_context (
    suite, gmp,
    gmp_authenticate_info_ext_c_returns_timeout_on_try_read_timeout);
  add_test_with_context (
    suite, gmp, gmp_authenticate_info_ext_c_returns_error_on_read_failure);
  add_test_with_context (
    suite, gmp, gmp_authenticate_info_ext_c_returns_error_when_status_empty);
  add_test_with_context (suite, gmp,
                         gmp_authenticate_info_ext_c_returns_2_on_auth_failure);
  add_test_with_context (
    suite, gmp,
    gmp_authenticate_info_ext_c_leaves_jwt_null_when_requested_but_missing);
  add_test_with_context (
    suite, gmp,
    gmp_authenticate_info_ext_c_leaves_optional_outputs_null_when_absent);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
