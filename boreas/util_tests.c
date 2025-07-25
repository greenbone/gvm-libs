/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "util.c"

#include <arpa/inet.h>
#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (util);
BeforeEach (util)
{
}
AfterEach (util)
{
}

__attribute__ ((weak)) int
__real_socket (__attribute__ ((unused)) int domain,
               __attribute__ ((unused)) int type,
               __attribute__ ((unused)) int protocol);

__attribute__ ((weak)) int
__real_setsockopt (__attribute__ ((unused)) int sockfd,
                   __attribute__ ((unused)) int level,
                   __attribute__ ((unused)) int optname,
                   __attribute__ ((unused)) const void *optval,
                   __attribute__ ((unused)) socklen_t optlen);

bool g_socket_use_real = true;
int
__wrap_socket (__attribute__ ((unused)) int domain,
               __attribute__ ((unused)) int type,
               __attribute__ ((unused)) int protocol);
int
__wrap_socket (__attribute__ ((unused)) int domain,
               __attribute__ ((unused)) int type,
               __attribute__ ((unused)) int protocol)
{
  if (g_socket_use_real)
    return __real_socket (domain, type, protocol);

  return (int) mock (domain, type, protocol);
}

bool g_setsockopt_use_real = true;
int
__wrap_setsockopt (__attribute__ ((unused)) int sockfd,
                   __attribute__ ((unused)) int level,
                   __attribute__ ((unused)) int optname,
                   __attribute__ ((unused)) const void *optval,
                   __attribute__ ((unused)) socklen_t optlen);
int
__wrap_setsockopt (__attribute__ ((unused)) int sockfd,
                   __attribute__ ((unused)) int level,
                   __attribute__ ((unused)) int optname,
                   __attribute__ ((unused)) const void *optval,
                   __attribute__ ((unused)) socklen_t optlen)
{
  if (g_setsockopt_use_real)
    return __real_setsockopt (sockfd, level, optname, optval, optlen);

  return (int) mock (sockfd, level, optname, optval, optlen);
}

/* in_cksum */

Ensure (util, in_cksum_small)
{
  int len;
  // https://web.archive.org/web/20020916085726/http://www.netfor2.com/checksum.html
  uint16_t data[] = {0x0100, 0xF203, 0xF4F5, 0xF6F7};

  len = sizeof (data); // len is in bytes
  assert_that (in_cksum ((uint16_t *) data, len), is_equal_to (0x210E));
}

Ensure (util, in_cksum_bigger)
{
  int len;
  // https://en.wikipedia.org/wiki/Internet_checksum
  uint16_t data[] = {0x4500, 0x0073, 0x0000, 0x4000, 0x4011,
                     0xC0A8, 0x0001, 0xC0A8, 0x00C7};

  len = sizeof (data); // len is in bytes
  assert_that (in_cksum ((uint16_t *) data, len), is_equal_to (0xB861));
}

/* set_all_needed_sockets */

Ensure (util, set_all_needed_sockets)
{
  g_socket_use_real = false;
  g_setsockopt_use_real = false;

  alive_test_t alive_test;
  scanner_t scanner = {0};

  /* All methods set. */
  alive_test = ALIVE_TEST_TCP_ACK_SERVICE | ALIVE_TEST_ICMP | ALIVE_TEST_ARP
               | ALIVE_TEST_CONSIDER_ALIVE | ALIVE_TEST_TCP_SYN_SERVICE;
  expect (__wrap_socket, will_return (5), times (8));
  expect (__wrap_setsockopt, will_return (5), times (10));
  set_all_needed_sockets (&scanner, alive_test);

  /* Only one method set. */
  alive_test = ALIVE_TEST_TCP_ACK_SERVICE;
  expect (__wrap_socket, will_return (5), times (4));
  expect (__wrap_setsockopt, will_return (5), times (6));
  set_all_needed_sockets (&scanner, alive_test);

  /* ALIVE_TEST_CONSIDER_ALIVE set. */
  alive_test = ALIVE_TEST_CONSIDER_ALIVE;
  never_expect (__wrap_socket);
  never_expect (__wrap_setsockopt);
  never_expect (set_socket);
  set_all_needed_sockets (&scanner, alive_test);

  g_socket_use_real = true;
  g_setsockopt_use_real = true;
}

Ensure (util, set_socket)
{
  g_setsockopt_use_real = false;
  g_socket_use_real = false;
  int socket_location;

  /* socket() successful. */
  expect (__wrap_socket, will_return (5));
  expect (__wrap_setsockopt);
  expect (__wrap_setsockopt);
  assert_that (set_socket (TCPV4, &socket_location), is_equal_to (0));

  /* socket() error. */
  expect (__wrap_socket, will_return (-5));
  never_expect (__wrap_setsockopt);
  assert_that (set_socket (TCPV4, &socket_location),
               is_equal_to (BOREAS_OPENING_SOCKET_FAILED));
  g_socket_use_real = true;
  g_setsockopt_use_real = true;
}

Ensure (util, get_source_addr_v4)
{
  int udpv4soc;
  struct in_addr dst;
  struct in_addr src;

  /* Open socket. */
  set_socket (UDPV4, &udpv4soc);

  /* Destination is localhost. */
  src.s_addr = INADDR_ANY;
  dst.s_addr = inet_addr ("127.0.0.1");
  get_source_addr_v4 (&udpv4soc, &dst, &src);
  assert_that (src.s_addr, is_not_equal_to (INADDR_ANY));

  /* Destination is example.com. */
  src.s_addr = INADDR_ANY;
  dst.s_addr = inet_addr ("93.184.216.34");
  get_source_addr_v4 (&udpv4soc, &dst, &src);
  assert_that (src.s_addr, is_not_equal_to (INADDR_ANY));

  /* Close socket. */
  close (udpv4soc);
}

Ensure (util, get_source_addr_v6)
{
  int udpv6soc;
  struct in6_addr dst;
  struct in6_addr src;
  boreas_error_t error;

  /* Open socket. */
  set_socket (UDPV6, &udpv6soc);

  /* Localhost. */
  inet_pton (AF_INET6, "::FFFF:127.0.0.1", &(dst));
  error = get_source_addr_v6 (&udpv6soc, &dst, &src);
  assert_that (error, is_equal_to (NO_ERROR));
  assert_that (!IN6_IS_ADDR_UNSPECIFIED (&src));

  /* Dependent on local IPv6 configuration. */
  // inet_pton (AF_INET6, "2001:0db8:0:f101::2", &(dst));
  // error = get_source_addr_v6 (&udpv6soc, &dst, &src);
  // assert_that (error, is_equal_to (NO_ERROR));
  // assert_that (!IN6_IS_ADDR_UNSPECIFIED (&src));

  /* Close socket. */
  close (udpv6soc);
}

Ensure (util, fill_ports_array)
{
  GArray *ports_garray = NULL;
  const gchar *port_list = NULL;
  GPtrArray *portranges_array = NULL;

  /* Port list used in alivedetection.c. */
  port_list = "80,137,587,3128,8081";
  assert_that (validate_port_range (port_list), is_equal_to (0));
  ports_garray = g_array_new (FALSE, TRUE, sizeof (uint16_t));
  portranges_array = port_range_ranges (port_list);
  assert_that (portranges_array, is_not_null);
  /* Fill ports array with ports from the ranges. */
  g_ptr_array_foreach (portranges_array, fill_ports_array, ports_garray);
  array_free (portranges_array);
  assert_that (ports_garray->len, is_equal_to (5));
  assert_that (g_array_index (ports_garray, uint16_t, 0), is_equal_to (80));
  assert_that (g_array_index (ports_garray, uint16_t, 4), is_equal_to (8081));
  g_array_free (ports_garray, TRUE);

  /* Random port list. Duplicates are not removed. */
  /* 1,2,5,6,10,11,12,10,10 */
  port_list = "1-2,T:5-6,U:10-12,T:10,10";
  assert_that (validate_port_range (port_list), is_equal_to (0));
  ports_garray = g_array_new (FALSE, TRUE, sizeof (uint16_t));
  portranges_array = port_range_ranges (port_list);
  assert_that (portranges_array, is_not_null);
  /* Fill ports array with ports from the ranges. */
  g_ptr_array_foreach (portranges_array, fill_ports_array, ports_garray);
  array_free (portranges_array);
  assert_that (ports_garray->len, is_equal_to (9));
  assert_that (g_array_index (ports_garray, uint16_t, 0), is_equal_to (1));
  assert_that (g_array_index (ports_garray, uint16_t, 4), is_equal_to (10));
  assert_that (g_array_index (ports_garray, uint16_t, 7), is_equal_to (10));
  assert_that (g_array_index (ports_garray, uint16_t, 8), is_equal_to (10));
  g_array_free (ports_garray, TRUE);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, util, in_cksum_small);
  add_test_with_context (suite, util, in_cksum_bigger);
  add_test_with_context (suite, util, fill_ports_array);
  add_test_with_context (suite, util, set_all_needed_sockets);
  add_test_with_context (suite, util, set_socket);
  add_test_with_context (suite, util, get_source_addr_v4);
  add_test_with_context (suite, util, get_source_addr_v6);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
