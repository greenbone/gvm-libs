/* Copyright (C) 2009-2021 Greenbone Networks GmbH
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
  assert_that (gvm_hosts_new (""), is_not_null);
  assert_that (gvm_hosts_new ("172.10.1.1"), is_not_null);
  assert_that (gvm_hosts_new ("172.10.1.1/24"), is_not_null);
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

/* Test suite. */

int
main (int argc, char **argv)
{
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

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
