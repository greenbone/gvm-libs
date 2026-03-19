/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "util.h"

#include "../base/networking.h" /* for range_t */
#include "alivedetection.h"
#include "boreas_error.h"

#include <errno.h>
#include <glib.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>           /* for if_nametoindex() */
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm boreas"

static boreas_error_t
set_socket (socket_type_t, int *);

/**
 * @brief Checksum calculation.
 *
 * From W.Richard Stevens "UNIX NETWORK PROGRAMMING" book. libfree/in_cksum.c
 * TODO: Section 8.7 of TCPv2 has more efficient implementation
 *
 * @param[in]  addr  Data to checksum over.
 * @param[in]  len   Length of data in bytes.
 *
 * @return Checksum in bytes.
 **/
uint16_t
in_cksum (uint16_t *addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return answer;
}

/**
 * @brief Get the source mac address of the given interface
 * or of the first non lo interface.
 *
 * @param interface Interface to get mac address from or NULL if first non lo
 * interface should be used.
 * @param[out]  mac Location where to store mac address.
 *
 * @return 0 on success, -1 on error.
 */
int
get_source_mac_addr (char *interface, uint8_t *mac)
{
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  int interface_provided = 0;

  if (interface)
    interface_provided = 1;

  if (getifaddrs (&ifaddr) == -1)
    {
      g_debug ("%s: getifaddr failed: %s", __func__, strerror (errno));
      return -1;
    }
  else
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)
              && !(ifa->ifa_flags & (IFF_LOOPBACK)))
            {
              if (interface_provided)
                {
                  if (g_strcmp0 (interface, ifa->ifa_name) == 0)
                    {
                      struct sockaddr_ll *s =
                        (struct sockaddr_ll *) ifa->ifa_addr;
                      memcpy (mac, s->sll_addr, 6 * sizeof (uint8_t));
                    }
                }
              else
                {
                  struct sockaddr_ll *s = (struct sockaddr_ll *) ifa->ifa_addr;
                  memcpy (mac, s->sll_addr, 6 * sizeof (uint8_t));
                }
            }
        }
      freeifaddrs (ifaddr);
    }
  return 0;
}

/**
 * @brief Figure out source address for given destination.
 *
 * This function uses a well known trick for getting the source address used
 * for a given destination by calling connect() and getsockname() on an udp
 * socket.
 *
 * @param[in]   udpv6soc  Location of the socket to use.
 * @param[in]   dst       Destination address.
 * @param[out]  src       Source address.
 *
 * @return 0 on success, boreas_error_t on failure.
 */
boreas_error_t
get_source_addr_v6 (int *udpv6soc, struct in6_addr *dst, struct in6_addr *src)
{
  struct sockaddr_storage storage;
  struct sockaddr_in6 sin;
  socklen_t sock_len;
  boreas_error_t error;

  memset (&sin, 0, sizeof (struct sockaddr_in6));
  sin.sin6_family = AF_INET6;
  sin.sin6_addr = *dst;
  sin.sin6_port = htons (9); /* discard port (see RFC 863) */
  memcpy (&storage, &sin, sizeof (sin));

  error = NO_ERROR;
  sock_len = sizeof (storage);
  if (connect (*udpv6soc, (const struct sockaddr *) &storage, sock_len) < 0)
    {
      g_warning ("%s: connect() on udpv6soc failed: %s %d", __func__,
                 strerror (errno), errno);
      /* State of the socket is unspecified.  Close the socket and create a new
       * one. */
      if ((close (*udpv6soc)) != 0)
        {
          g_debug ("%s: Error in close(): %s", __func__, strerror (errno));
        }
      set_socket (UDPV6, udpv6soc);
      error = BOREAS_NO_SRC_ADDR_FOUND;
    }
  else
    {
      if (getsockname (*udpv6soc, (struct sockaddr *) &storage, &sock_len) < 0)
        {
          g_debug ("%s: getsockname() on updv6soc failed: %s", __func__,
                   strerror (errno));
          error = BOREAS_NO_SRC_ADDR_FOUND;
        }
    }

  if (!error)
    {
      /* Set source address. */
      memcpy (src, &((struct sockaddr_in6 *) (&storage))->sin6_addr,
              sizeof (struct in6_addr));

      /* Dissolve association so we can connect() on same socket again in later
       * call to get_source_addr_v4(). */
      sin.sin6_family = AF_UNSPEC;
      sock_len = sizeof (storage);
      memcpy (&storage, &sin, sizeof (sin));
      if (connect (*udpv6soc, (const struct sockaddr *) &storage, sock_len) < 0)
        g_debug ("%s: connect() on udpv6soc to dissolve association failed: %s",
                 __func__, strerror (errno));
    }

  return error;
}

/**
 * @brief Figure out source address for given destination.
 *
 * This function uses a well known trick for getting the source address used
 * for a given destination by calling connect() and getsockname() on an udp
 * socket.
 *
 * @param[in]   udpv4soc  Location of the socket to use.
 * @param[in]   dst       Destination address.
 * @param[out]  src       Source address.
 *
 * @return 0 on success, boreas_error_t on failure.
 */
boreas_error_t
get_source_addr_v4 (int *udpv4soc, struct in_addr *dst, struct in_addr *src)
{
  struct sockaddr_storage storage;
  struct sockaddr_in sin;
  socklen_t sock_len;
  boreas_error_t error;

  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = dst->s_addr;
  sin.sin_port = htons (9); /* discard port (see RFC 863) */
  memcpy (&storage, &sin, sizeof (sin));

  error = NO_ERROR;
  sock_len = sizeof (storage);
  if (connect (*udpv4soc, (const struct sockaddr *) &storage, sock_len) < 0)
    {
      g_warning ("%s: connect() on udpv4soc failed: %s", __func__,
                 strerror (errno));
      /* State of the socket is unspecified.  Close the socket and create a new
       * one. */
      if ((close (*udpv4soc)) != 0)
        {
          g_debug ("%s: Error in close(): %s", __func__, strerror (errno));
        }
      set_socket (UDPV4, udpv4soc);
      error = BOREAS_NO_SRC_ADDR_FOUND;
    }
  else
    {
      if (getsockname (*udpv4soc, (struct sockaddr *) &storage, &sock_len) < 0)
        {
          g_debug ("%s: getsockname() on updv4soc failed: %s", __func__,
                   strerror (errno));
          error = BOREAS_NO_SRC_ADDR_FOUND;
        }
    }

  if (!error)
    {
      /* Set source address. */
      memcpy (src, &((struct sockaddr_in *) (&storage))->sin_addr,
              sizeof (struct in_addr));

      /* Dissolve association so we can connect() on same socket again in later
       * call to get_source_addr_v4(). */
      sin.sin_family = AF_UNSPEC;
      sock_len = sizeof (storage);
      memcpy (&storage, &sin, sizeof (sin));
      if (connect (*udpv4soc, (const struct sockaddr *) &storage, sock_len) < 0)
        g_debug ("%s: connect() on udpv4soc to dissolve association failed: %s",
                 __func__, strerror (errno));
    }

  return error;
}

/**
 * @brief Put all ports of a given port range into the ports array.
 *
 * @param range Pointer to a range_t.
 * @param ports_array Pointer to an GArray.
 */
void
fill_ports_array (gpointer range, gpointer ports_array)
{
  gboolean range_exclude;
  int range_start;
  int range_end;
  int i;
  /* Use uint16_t for port array elements. tcphdr port type is uint16_t. */
  uint16_t port_sized;

  range_start = ((range_t *) range)->start;
  range_end = ((range_t *) range)->end;
  range_exclude = ((range_t *) range)->exclude;

  /* If range should be excluded do not use it. */
  if (range_exclude)
    return;

  /* Only single port in range. */
  if (range_end == 0 || (range_start == range_end))
    {
      port_sized = (uint16_t) range_start;
      g_array_append_val (ports_array, port_sized);
      return;
    }
  else
    {
      for (i = range_start; i <= range_end; i++)
        {
          port_sized = (uint16_t) i;
          g_array_append_val (ports_array, port_sized);
        }
    }
}

boreas_error_t
close_all_needed_sockets (scanner_t *scanner, alive_test_t alive_test)
{
  boreas_error_t error;

  error = NO_ERROR;

  if (alive_test & ALIVE_TEST_ICMP)
    {
      if ((close (scanner->icmpv4soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
      if ((close (scanner->icmpv6soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
    }

  if ((alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
      || (alive_test & ALIVE_TEST_TCP_SYN_SERVICE))
    {
      if ((close (scanner->tcpv4soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
      if ((close (scanner->tcpv6soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
      if ((close (scanner->udpv4soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
      if ((close (scanner->udpv6soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
    }

  if ((alive_test & ALIVE_TEST_ARP))
    {
      if ((close (scanner->arpv4soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
      if ((close (scanner->arpv6soc)) != 0)
        {
          g_warning ("%s: Error in close(): %s", __func__, strerror (errno));
          error = -1;
        }
    }

  return error;
}

/**
 * @brief Set the SO_BROADCAST socket option for given socket.
 *
 * @param socket  The socket to apply the option to.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
set_broadcast (int socket)
{
  boreas_error_t error = NO_ERROR;
  int broadcast = 1;
  if (setsockopt (socket, SOL_SOCKET, SO_BROADCAST, &broadcast,
                  sizeof (broadcast))
      < 0)
    {
      g_warning ("%s: failed to set socket option SO_BROADCAST: %s", __func__,
                 strerror (errno));
      error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
    }
  return error;
}

/**
 * @brief Set a new socket of specified type.
 *
 * @param[in] socket_type  What type of socket to get.
 *
 * @param[out] scanner_socket  Location to save the socket into.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
set_socket (socket_type_t socket_type, int *scanner_socket)
{
  boreas_error_t error = NO_ERROR;
  int soc = -1;
  switch (socket_type)
    {
    case UDPV4:
      {
        soc = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open UDPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case UDPV6:
      {
        soc = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open UDPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case TCPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_warning ("%s: failed to open TCPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
        else
          {
            int opt = 1;
            if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt,
                            sizeof (opt))
                < 0)
              {
                g_warning (
                  "%s: failed to set socket options on TCPV4 socket: %s",
                  __func__, strerror (errno));
                error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
              }
          }
      }
      break;
    case TCPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_warning ("%s: failed to open TCPV6 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
        else
          {
            int opt_on = 1;
            if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL,
                            (char *) &opt_on, // IPV6_HDRINCL
                            sizeof (opt_on))
                < 0)
              {
                g_warning (
                  "%s: failed to set socket options on TCPV6 socket: %s",
                  __func__, strerror (errno));
                error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
              }
          }
      }
      break;
    case ICMPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open ICMPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case ARPV6:
    case ICMPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (soc < 0)
          {
            g_warning ("%s: failed to open ARPV6/ICMPV6 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case ARPV4:
      {
        soc = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
        if (soc < 0)
          {
            g_warning ("%s: failed to open ARPV4 socket: %s", __func__,
                       strerror (errno));
            return BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    default:
      error = BOREAS_OPENING_SOCKET_FAILED;
      break;
    }

  /* set SO_BROADCAST socket option. If not set we get permission denied error
   * on pinging broadcast address */
  if (!error)
    {
      error = set_broadcast (soc);
      if (error != 0)
        return error;
    }

  *scanner_socket = soc;
  return error;
}

boreas_error_t
set_udp6_socket (scanner_t *scanner)
{
  boreas_error_t error = NO_ERROR;
  error = set_socket (UDPV6, &(scanner->udpv6soc));
  return error;
}

boreas_error_t
init_ipv6_net_data (scanner_t *scanner, const char *net)
{
  struct in6_addr first, last;
  struct sockaddr_in6 socs;
  int soc;
  boreas_error_t error = NO_ERROR;
  // IPv6 net data for host discovery
  scanner->ipv6_net = g_malloc0 (sizeof (ipv6_net_data_t));
  scanner->ipv6_net->net = g_strdup (net);

  /* Get source address for IPv6 header. */
  gvm_cidr6_block_ips (scanner->ipv6_net->net, &first, &last);

  error = get_source_addr_v6 (&(scanner->udpv6soc), &first,
                              &(scanner->ipv6_net->src));
  if (error)
    {
      char destination_str[INET_ADDRSTRLEN];
      inet_ntop (AF_INET6, (const void *) &first, destination_str,
                 INET_ADDRSTRLEN);
      printf ("%s: Destination: %s. %s", __func__, destination_str,
              str_boreas_error (error));
      return BOREAS_INVALID_IPV6_NETWORK;
    }

  int opt_on = 1;
  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    {
      g_warning ("%s: failed to open ICPMV6 socket: %s", __func__,
                 strerror (errno));
      error = BOREAS_OPENING_SOCKET_FAILED;
    }

  if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL, (char *) &opt_on,
                  sizeof (opt_on))
      < 0)
    {
      g_warning ("%s: failed to set socket option IP_HDRINCL: %s", __func__,
                 strerror (errno));
      error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
    }

  // Enable multicast
  if (!error)
    {
      error = set_broadcast (soc);
      if (error != 0)
        return error;
    }

  // Create source address
  memset (&socs, 0, sizeof (socs));
  socs.sin6_family = AF_INET6;
  socs.sin6_addr = scanner->ipv6_net->src;
  // and set the source address to the socket
  if (bind (soc, (struct sockaddr *) &socs, sizeof (socs)) < 0)
    {
      g_warning ("%s: failed to bind socket to source address: %s", __func__,
                 strerror (errno));
      return BOREAS_BIND_SOCKET_FAILED;
    }
  scanner->icmpv6soc = soc;

  return error;
}

/**
 * @brief Set all sockets needed for the chosen detection methods.
 *
 * @param scanner     Reference to scanner struct.
 * @param alive_test  Methods of alive detection to use provided as bitflag.
 *
 * @return 0 on success, boreas_error_t on error.
 */
boreas_error_t
set_all_needed_sockets (scanner_t *scanner, alive_test_t alive_test)
{
  boreas_error_t error = NO_ERROR;
  if (alive_test & ALIVE_TEST_ICMP)
    {
      error = set_socket (ICMPV4, &(scanner->icmpv4soc));
      if (error != 0)
        return error;
      error = set_socket (ICMPV6, &(scanner->icmpv6soc));
      if (error != 0)
        return error;
    }

  if ((alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
      || (alive_test & ALIVE_TEST_TCP_SYN_SERVICE))
    {
      error = set_socket (TCPV4, &(scanner->tcpv4soc));
      if (error != 0)
        return error;
      error = set_socket (TCPV6, &(scanner->tcpv6soc));
      if (error != 0)
        return error;
      error = set_socket (UDPV4, &(scanner->udpv4soc));
      if (error != 0)
        return error;
      error = set_socket (UDPV6, &(scanner->udpv6soc));
      if (error != 0)
        return error;
    }

  if ((alive_test & ALIVE_TEST_ARP))
    {
      error = set_socket (ARPV4, &(scanner->arpv4soc));
      if (error != 0)
        return error;
      error = set_socket (ARPV6, &(scanner->arpv6soc));
      if (error != 0)
        return error;
    }

  return error;
}

/**
 * @brief Subtract two hashtables and count the remaining elements.
 *
 * The original hashtables are not changed during or after the count operation.
 *
 * @param A Base Hashtable.
 * @param B Hashtable to be subtracted from A.
 *
 * @return count of remaining elements in A-B.
 */
int
count_difference (GHashTable *hashtable_A, GHashTable *hashtable_B)
{
  int count = 0;

  GHashTableIter target_hosts_iter;
  gpointer key, value;

  for (g_hash_table_iter_init (&target_hosts_iter, hashtable_A);
       g_hash_table_iter_next (&target_hosts_iter, &key, &value);)
    {
      if (!g_hash_table_contains (hashtable_B, key))
        {
          count++;
        }
    }

  return count;
}

/**
 * @brief Check if socket send buffer is empty.
 *
 * @param[in] soc Socket.
 * @param[out] err Set to -1 on error.
 *
 * @return 1 if so_sndbug is empyt, else 0.
 */
static int
so_sndbuf_empty (int soc, int *err)
{
  int cur_so_sendbuf = -1;
  if (ioctl (soc, SIOCOUTQ, &cur_so_sendbuf) == -1)
    {
      g_warning ("%s: ioctl error: %s", __func__, strerror (errno));
      *err = -1;
      return 0;
    }
  return cur_so_sendbuf ? 0 : 1;
}

/**
 * @brief Wait until socket send buffer empty or timeout reached.
 *
 * @param soc     Socket.
 * @param timeout Timeout in seconds.
 */
void
wait_until_so_sndbuf_empty (int soc, int timeout)
{
  int cnt = 0;
  int err = 0;
  int empty;

  empty = so_sndbuf_empty (soc, &err);
  for (; !empty && (err != -1) && (cnt / 10 != timeout);
       empty = so_sndbuf_empty (soc, &err), cnt++)
    {
      usleep (100000);
    }
}

/**
 * @brief Check if the address is contained in the CIDR block
 *
 * @param cidr    a valid IPv6 CIDR-expressed block
 * @param address IPv6 address to check if it is contained.
 *
 * @return 1 if it is contained, 0 if not. Boreas error type on error;
 */
int
cidr6block_contains (const char *cidr, const char *address)
{
  struct in6_addr net, ip;
  unsigned int prefix_len = 0;

  if (gvm_cidr6_get_ip (cidr, &net) || gvm_cidr6_get_block (cidr, &prefix_len))

    g_debug ("Checking if %s belongs to the CIDR block %s", address, cidr);

  if (inet_pton (AF_INET6, address, &ip) != 1)
    return -1;

  const uint8_t *addr_bytes = (const uint8_t *) &ip;
  const uint8_t *net_bytes = (const uint8_t *) &net;

  int bytes_to_compare = prefix_len / 8;
  int bits_to_compare = prefix_len % 8;

  if (bytes_to_compare > 0)
    {
      if (memcmp (addr_bytes, net_bytes, bytes_to_compare) != 0)
        {
          return 0;
        }
    }

  if (bits_to_compare > 0)
    {
      uint8_t mask = 0xFF << (8 - bits_to_compare);
      if ((addr_bytes[bytes_to_compare] & mask)
          != (net_bytes[bytes_to_compare] & mask))
        {
          return 0;
        }
    }

  return 1; // All network bits match
}
