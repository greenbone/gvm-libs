/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "hosts.c"
#include "networking.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (hosts);
BeforeEach (hosts)
{
}
AfterEach (hosts)
{
}

/* make_hosts */

Ensure (hosts, gvm_hosts_new_never_returns_null)
{
  gvm_hosts_t *hosts;

  hosts = gvm_hosts_new ("");
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new ("172.10.1.1");
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new ("172.10.1.1/24");
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_get_host_type_returns_host_type_ipv4)
{
  assert_that (gvm_get_host_type ("192.168.0.4"), is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("1.1.1.1"), is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("0.0.0.0"), is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("255.255.255.255"),
               is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("10.1.1.1"), is_equal_to (HOST_TYPE_IPV4));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_ipv6)
{
  assert_that (gvm_get_host_type ("::ffee"), is_equal_to (HOST_TYPE_IPV6));
  assert_that (gvm_get_host_type ("0001:1:1:1::1"),
               is_equal_to (HOST_TYPE_IPV6));
}

#define TEN "0123456789"
#define SIXTY TEN TEN TEN TEN TEN TEN
#define HUNDRED TEN TEN TEN TEN TEN TEN TEN TEN TEN TEN

Ensure (hosts, gvm_get_host_type_returns_host_type_hostname)
{
  assert_that (gvm_get_host_type ("www.greenbone.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("www.example_underscore.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("www.example-dash.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("greenbone.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("g"), is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("123.com"), is_equal_to (HOST_TYPE_NAME));
  /* Lengths. */
  assert_that (gvm_get_host_type (SIXTY "123.short.enough.com"),
               is_equal_to (0));
  assert_that (gvm_get_host_type (SIXTY "." SIXTY "." SIXTY "." SIXTY "."
                                        "56789.com"),
               is_equal_to (0));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_cidr_block)
{
  assert_that (gvm_get_host_type ("192.168.0.0/24"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("1.1.1.1/8"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("192.168.1.128/25"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("10.0.0.1/16"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("10.1.1.0/30"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_cidr6_block)
{
  assert_that (gvm_get_host_type ("::ffee:1/64"),
               is_equal_to (HOST_TYPE_CIDR6_BLOCK));
  assert_that (gvm_get_host_type ("2001:db8::/78"),
               is_equal_to (HOST_TYPE_CIDR6_BLOCK));
  assert_that (gvm_get_host_type ("2001:db8:0000:0000:001f:ffff:ffff:1/1"),
               is_equal_to (HOST_TYPE_CIDR6_BLOCK));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range_short)
{
  assert_that (gvm_get_host_type ("192.168.10.1-9"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("192.168.10.1-50"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("192.168.10.1-255"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("1.1.1.1-9"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("1.1.1.1-50"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("1.1.1.1-255"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("255.255.255.1-9"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("255.255.255.1-50"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("255.255.255.1-255"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range6_short)
{
  assert_that (gvm_get_host_type ("::ffee:1-fe50"),
               is_equal_to (HOST_TYPE_RANGE6_SHORT));
  assert_that (gvm_get_host_type ("2000::-ffff"),
               is_equal_to (HOST_TYPE_RANGE6_SHORT));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range_long)
{
  assert_that (gvm_get_host_type ("192.168.10.1-192.168.10.9"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("192.168.10.1-192.168.10.50"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("192.168.10.1-192.168.10.255"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("1.1.1.1-1.1.1.9"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("1.1.1.1-1.1.1.50"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("1.1.1.1-1.1.1.255"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("255.255.255.1-255.255.255.9"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("255.255.255.1-255.255.255.50"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("255.255.255.1-255.255.255.255"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range6_long)
{
  assert_that (
    gvm_get_host_type ("2001:db0::-2001:0dbf:ffff:ffff:ffff:ffff:ffff:ffff"),
    is_equal_to (HOST_TYPE_RANGE6_LONG));
  assert_that (gvm_get_host_type ("::1:200:7-::1:205:500"),
               is_equal_to (HOST_TYPE_RANGE6_LONG));
}

Ensure (hosts, gvm_get_host_type_returns_error)
{
  assert_that (gvm_get_host_type (""), is_equal_to (-1));
  assert_that (gvm_get_host_type ("."), is_equal_to (-1));

  /* Invalid chars. */
  assert_that (gvm_get_host_type ("a,b"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("="), is_equal_to (-1));

  /* Numeric TLD. */
  assert_that (gvm_get_host_type ("a.123"), is_equal_to (-1));

  /* IP with too many parts. */
  assert_that (gvm_get_host_type ("192.168.10.1.1"), is_equal_to (-1));

  /* IP with numbers out of bounds. */
  assert_that (gvm_get_host_type ("256.168.10.1"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.256.10.1"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.168.256.1"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.168.10.256"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.168.10.855"), is_equal_to (-1));

  /* Lengths. */
  assert_that (gvm_get_host_type (SIXTY "1234.too.long.com"), is_equal_to (-1));
  assert_that (gvm_get_host_type (SIXTY "." SIXTY "." SIXTY "." SIXTY "."
                                        "567890.com"),
               is_equal_to (-1));
}

Ensure (hosts, gvm_hosts_new_with_max_returns_success)
{
  gvm_hosts_t *hosts;

  hosts = gvm_hosts_new_with_max ("127.0.0.1", 1);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new_with_max ("127.0.0.1", 2000);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new_with_max ("127.0.0.1,127.0.0.2", 2);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new_with_max ("127.0.0.1, 127.0.0.2", 2);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_new_with_max_returns_error)
{
  /* Host error. */
  assert_that (gvm_hosts_new_with_max ("a.123", 2), is_null);

  /* More than max_hosts hosts. */
  assert_that (gvm_hosts_new_with_max ("127.0.0.1, 127.0.0.2", 1), is_null);

  /* Wrong separator. */
  assert_that (gvm_hosts_new_with_max ("127.0.0.1 127.0.0.2", 2), is_null);
  assert_that (gvm_hosts_new_with_max ("127.0.0.1|127.0.0.2", 2), is_null);
}

// This is a macro so the line number below is clear on failure.
#define ASSERT_HOST_EQUALS(hosts, i, string)                                     \
{                                                                                \
  gchar *value;                                                                  \
                                                                                 \
  value = gvm_host_value_str (hosts->hosts[i]);                                  \
  assert_true_with_message (g_strcmp0 (value, string) == 0,                      \
                            "Expected hosts->hosts[%d] to be %s but it was %s",  \
                            i, string, value);                                   \
  g_free (value);                                                                \
}

static int
host_value_eq (gvm_host_t *host, gchar *string)
{
  int ret;
  gchar *value;

  value = gvm_host_value_str (host);
  ret = g_strcmp0 (value, string);
  g_free (value);
  return ret;
}

Ensure (hosts, gvm_hosts_move_host_to_end)
{
  gvm_hosts_t *hosts = NULL;
  gvm_host_t *host = NULL;
  int totalhosts;
  size_t current;

  hosts = gvm_hosts_new ("192.168.0.0/28");

  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  ASSERT_HOST_EQUALS (hosts, 3, "192.168.0.4");
  ASSERT_HOST_EQUALS (hosts, 4, "192.168.0.5");
  ASSERT_HOST_EQUALS (hosts, 5, "192.168.0.6");
  ASSERT_HOST_EQUALS (hosts, 6, "192.168.0.7");
  ASSERT_HOST_EQUALS (hosts, 7, "192.168.0.8");
  ASSERT_HOST_EQUALS (hosts, 8, "192.168.0.9");
  ASSERT_HOST_EQUALS (hosts, 9, "192.168.0.10");
  ASSERT_HOST_EQUALS (hosts, 10, "192.168.0.11");
  ASSERT_HOST_EQUALS (hosts, 11, "192.168.0.12");
  ASSERT_HOST_EQUALS (hosts, 12, "192.168.0.13");
  ASSERT_HOST_EQUALS (hosts, 13, "192.168.0.14");

  // Get first host
  host = gvm_hosts_next (hosts);

  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (14));

  while (host_value_eq (host, "192.168.0.9"))
    {
      host = gvm_hosts_next (hosts);
    }
  assert_that (host_value_eq (host, "192.168.0.9"),
               is_equal_to (0));

  current = hosts->current;
  gvm_hosts_move_current_host_to_end (hosts);
  assert_that (hosts->current, is_equal_to (current - 1));

  host = gvm_hosts_next (hosts);
  assert_that (host_value_eq (host, "192.168.0.10"),
               is_equal_to (0));
  assert_that (host_value_eq (hosts->hosts[totalhosts - 1],
                              "192.168.0.9"),
               is_equal_to (0));

  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  ASSERT_HOST_EQUALS (hosts, 3, "192.168.0.4");
  ASSERT_HOST_EQUALS (hosts, 4, "192.168.0.5");
  ASSERT_HOST_EQUALS (hosts, 5, "192.168.0.6");
  ASSERT_HOST_EQUALS (hosts, 6, "192.168.0.7");
  ASSERT_HOST_EQUALS (hosts, 7, "192.168.0.8");
  ASSERT_HOST_EQUALS (hosts, 8, "192.168.0.10");
  ASSERT_HOST_EQUALS (hosts, 9, "192.168.0.11");
  ASSERT_HOST_EQUALS (hosts, 10, "192.168.0.12");
  ASSERT_HOST_EQUALS (hosts, 11, "192.168.0.13");
  ASSERT_HOST_EQUALS (hosts, 12, "192.168.0.14");
  ASSERT_HOST_EQUALS (hosts, 13, "192.168.0.9");

  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_allowed_only)
{
  gvm_hosts_t *hosts = NULL;
  gvm_host_t *host = NULL;
  int totalhosts;
  GSList *removed = NULL;
  gchar *value;

  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");

  removed = gvm_hosts_allowed_only (hosts, NULL, NULL);
  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (3));

  removed = gvm_hosts_allowed_only (hosts, "192.168.0.2", NULL);
  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (2));
  assert_that (g_slist_length (removed), is_equal_to (1));
  g_slist_free_full (removed, g_free);

  removed = gvm_hosts_allowed_only (hosts, NULL, "192.168.0.3");
  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (1));
  assert_that (g_slist_length (removed), is_equal_to (1));
  g_slist_free_full (removed, g_free);

  host = gvm_hosts_next (hosts);
  value = gvm_host_value_str (host);
  assert_that (g_strcmp0 (value, "192.168.0.3"),
               is_equal_to (0));
  g_free (value);

  gvm_hosts_free (hosts);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, hosts, gvm_hosts_new_never_returns_null);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_ipv4);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_ipv6);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_hostname);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_cidr_block);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_cidr6_block);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range_short);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range6_short);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range_long);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range6_long);
  add_test_with_context (suite, hosts, gvm_get_host_type_returns_error);

  add_test_with_context (suite, hosts, gvm_hosts_new_with_max_returns_error);
  add_test_with_context (suite, hosts, gvm_hosts_new_with_max_returns_success);

  add_test_with_context (suite, hosts, gvm_hosts_move_host_to_end);
  add_test_with_context (suite, hosts, gvm_hosts_allowed_only);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
