/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "openvasd.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (openvasd);
BeforeEach (openvasd)
{
}

AfterEach (openvasd)
{
}

/* parse_results */

Ensure (openvasd, parse_results_handles_details)
{
  const gchar *str;
  GSList *results;
  openvasd_result_t result;


  results = NULL;

  str = "[ {"
    "  \"id\": 16,"
    "  \"type\": \"host_detail\","
    "  \"ip_address\": \"192.168.0.101\","
    "  \"hostname\": \"g\","
    "  \"oid\": \"1.3.6.1.4.1.25623.1.0.103997\","
    "  \"message\": \"<host><detail><name>MAC</name><value>94:E6:F7:67:4B:C0</value><source><type>nvt</type><name>1.3.6.1.4.1.25623.1.0.103585</name><description>Nmap MAC Scan</description></source></detail></host>\","
    "  \"detail\": {"
    "    \"name\": \"MAC\","
    "    \"value\": \"00:1A:2B:3C:4D:5E\","
    "    \"source\": {"
    "      \"type\": \"nvt\","
    "      \"name\": \"1.3.6.1.4.1.25623.1.0.103585\","
    "      \"description\": \"Nmap MAC Scan\""
    "    }"
    "  }"
    "} ]";

  parse_results (str, &results);

  assert_that (g_slist_length (results), is_equal_to (1));

  result = results->data;
  assert_that (result->detail_name, is_equal_to_string ("MAC"));
  assert_that (result->detail_value, is_equal_to_string ("00:1A:2B:3C:4D:5E"));
  assert_that (result->detail_source_type, is_equal_to_string ("nvt"));
  assert_that (result->detail_source_name, is_equal_to_string ("1.3.6.1.4.1.25623.1.0.103585"));
  assert_that (result->detail_source_description, is_equal_to_string ("Nmap MAC Scan"));

  if (g_slist_length (results))
    g_slist_free_full (results, (GDestroyNotify) openvasd_result_free);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, openvasd, parse_results_handles_details);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
