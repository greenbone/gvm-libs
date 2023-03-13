/* Portions Copyright (C) 2021-2022 Greenbone AG
 * Based on work Copyright (C) Thomas Habets <thomas@habets.se>
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
 * @brief implementation of arp ping.
 *
 * Most of the functions are modified versions of functions found in
 * https://github.com/ThomasHabets/arping/tree/arping-2.19/src.
 */

#include "arp.h"

#include "../base/networking.h" /* for gvm_source_addr() */

#include <errno.h>
#include <glib.h>
#include <ifaddrs.h>
#include <libnet.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm boreas"

static libnet_t *libnet = 0;

static uint32_t dstip;           /* target IP */
static uint8_t dstmac[ETH_ALEN]; /* ethxmas */

/* autodetected, overridden by gvm_source_addr if openvas source_iface was set*/
static uint32_t srcip;
static uint8_t srcmac[ETH_ALEN]; /* autodetected */

static const uint8_t ethnull[ETH_ALEN] = {0, 0, 0, 0, 0, 0};
static const uint8_t ethxmas[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const char *ip_broadcast = "255.255.255.255";

/**
 * @brief Strip newline at end of string.
 *
 * Some Libnet error messages end with a newline. Strip that in place.
 *
 * @param s String to strip newline from.
 */
static void
strip_newline (char *s)
{
  size_t n;
  for (n = strlen (s); n && (s[n - 1] == '\n'); --n)
    {
      s[n - 1] = 0;
    }
}

/**
 * @brief Init libnet.
 *
 * Init libnet with specified ifname. Destroy if already inited.
 * If this function retries with different parameter it will preserve
 * the original error message and print that.
 * Call with recursive=0.
 *
 * @param ifname    Interface name to use
 * @param recursive Only used inside do_libnet_init. Use 0.
 *
 * @return -1 on failure, 0 on success.
 */
static int
do_libnet_init (const char *ifname, int recursive)
{
  char ebuf[LIBNET_ERRBUF_SIZE];
  ebuf[0] = 0;
  if (libnet)
    {
      /* Probably going to switch interface from temp to real. */
      libnet_destroy (libnet);
      libnet = 0;
    }

  /* Try libnet_init() even though we aren't root. We may have
   * a capability or something. */
  if (!(libnet = libnet_init (LIBNET_LINK, (char *) ifname, ebuf)))
    {
      strip_newline (ebuf);
      if (!ifname)
        {
          /* Sometimes libnet guesses an interface that it then
           * can't use. Work around that by attempting to
           * use "lo". */
          do_libnet_init ("lo", 1);
          if (libnet != NULL)
            {
              return 0;
            }
        }
      else if (recursive)
        {
          /* Continue original execution to get that
           * error message. */
          return 0;
        }
      g_debug ("%s: libnet_init(LIBNET_LINK, %s): %s", __func__,
               ifname ? ifname : "<null>", ebuf);
      if (getuid () && geteuid ())
        {
          g_warning ("%s: you may need to run as root", __func__);
        }
      return -1;
    }
  return 0;
}

/**
 * @brief Resolve address.
 *
 * @param[in]   l     libnet_t.
 * @param[in]   name  IP string or addr name.
 * @param[out]  addr  Resolved ipv4 addr.
 *
 * @return 1 on success, 0 on failure.
 */
static int
xresolve (libnet_t *l, const char *name, int r, uint32_t *addr)
{
  if (!strcmp (ip_broadcast, name))
    {
      *addr = 0xffffffff;
      return 1;
    }
  *addr = libnet_name2addr4 (l, (char *) name, r);
  return *addr != 0xffffffff;
}

/**
 * @brief Format a MAC address to human readable format.
 *
 * @param[in] mac   MAC to format.
 * @param[in] buf   Buffer to store formatted MAC in.
 * @param[in] bufze Size of Buffer.
 *
 * @return Formatted MAC string stored in buf.
 */
static char *
format_mac (const unsigned char *mac, char *buf, size_t bufsize)
{
  snprintf (buf, bufsize, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1],
            mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

/**
 * @brief  Send ARP who-has.
 */
static void
pingip_send ()
{
  libnet_ptag_t arp = 0, eth = 0;

  // Padding size chosen fairly arbitrarily.
  // Without this padding some systems (e.g. Raspberry Pi 3
  // wireless interface) failed. dmesg said:
  //   arping: packet size is too short (42 <= 50)
  const uint8_t padding[16] = {0};

  if (-1
      == (libnet_build_arp (ARPHRD_ETHER, ETHERTYPE_IP, ETH_ALEN, IP_ALEN,
                            ARPOP_REQUEST, srcmac, (uint8_t *) &srcip,
                            (uint8_t *) ethnull, (uint8_t *) &dstip, padding,
                            sizeof padding, libnet, arp)))
    {
      g_warning ("%s: libnet_build_arp(): %s", __func__,
                 libnet_geterror (libnet));
    }

  eth = libnet_build_ethernet (dstmac, srcmac, ETHERTYPE_ARP,
                               NULL, // payload
                               0,    // payload size
                               libnet, eth);
  if (-1 == eth)
    {
      g_warning ("%s: %s: %s", __func__, "libnet_build_ethernet()",
                 libnet_geterror (libnet));
    }
  if (-1 == libnet_write (libnet))
    {
      g_warning ("%s: libnet_write(): %s", __func__, libnet_geterror (libnet));
    }
}

/**
 * @brief Send arp ping using libnet.
 *
 * @param dst Destination address as string.
 *
 */
void
send_arp_v4 (const char *dst_str)
{
  char ebuf[LIBNET_ERRBUF_SIZE + PCAP_ERRBUF_SIZE];
  char *cp;
  char *ifname = NULL;
  char *target = NULL;
  char mac_debug_buf[128];

  char pcap_ebuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp = NULL;
  /* default interface when no interface is found via arp_lookupdev() */
  static char ifname_default[IF_NAMESIZE] = {0};
  /* interface used for previous ping */
  static char ifname_prev[IF_NAMESIZE] = {0};

  ebuf[0] = 0;

  /* set globals */
  srcip = 0;
  dstip = 0xffffffff;
  memcpy (dstmac, ethxmas, ETH_ALEN);

  /* set src IP if we have global openvas src ip */
  gvm_source_addr (&srcip);

  /* init libnet if not already done */
  if (NULL == libnet)
    {
      do_libnet_init (ifname, 0);
    }

  /* init default interface if not already done */
  if (!*ifname_default)
    {
      if (pcap_findalldevs (&alldevsp, pcap_ebuf) < 0)
        g_message ("%s: Error pcap_findalldevs(): %s", __func__, pcap_ebuf);
      if (alldevsp != NULL)
        {
          memcpy (ifname_default, alldevsp->name, IF_NAMESIZE);
          pcap_freealldevs (alldevsp);
        }
    }

  /* Make sure dstip and dst_str like each other */
  if (!xresolve (libnet, dst_str, LIBNET_DONT_RESOLVE, &dstip))
    {
      g_warning ("%s: Can't resolve %s. No ARP ping done for this addr.",
                 __func__, dst_str);
      return;
    }
  target = g_strdup (libnet_addr2name4 (dstip, 0));

  /* Get some good iface. */
  if (!ifname)
    {
      struct sockaddr_storage target_addr;
      struct sockaddr_in sin_dst;
      sin_dst.sin_family = AF_INET;
      sin_dst.sin_addr.s_addr = dstip;
      memcpy (&target_addr, &sin_dst, sizeof (sin_dst));

      ifname = gvm_get_outgoing_iface (&target_addr);
      strip_newline (ebuf);
      if (!ifname)
        {
          g_debug ("%s: %s Trying to use guessed interface instead.", __func__,
                   ebuf);
        }
      if (!ifname)
        {
          /* Only set ifname if ifname_default str is not empty. */
          if (*ifname_default)
            ifname = g_strdup (ifname_default);
        }
      if (!ifname)
        {
          g_warning ("%s: Gave up looking for interface"
                     " to use: %s. Address '%s' will be skipped.",
                     __func__, ebuf, target);
          g_free (target);
          return;
        }
      /* check for other probably-not interfaces */
      if (!strcmp (ifname, "ipsec") || !strcmp (ifname, "lo"))
        {
          g_warning ("%s: %s looks like the wrong "
                     "interface to use. Using it anyway this time.",
                     __func__, ifname);
        }
    }

  /*
   * Init libnet again if the interface is not the same as the previously used
   * one.
   */
  if (!*ifname_prev || 0 != g_strcmp0 (ifname, ifname_prev))
    {
      memcpy (ifname_prev, ifname, IF_NAMESIZE);
      do_libnet_init (ifname, 0);
    }

  if (!(cp = (char *) libnet_get_hwaddr (libnet)))
    {
      g_warning ("%s: libnet_get_hwaddr(): %s. Address '%s' will be skipped.",
                 __func__, libnet_geterror (libnet), target);
      g_free (target);
      g_free (ifname);
      return;
    }
  memcpy (srcmac, cp, ETH_ALEN);

  if (srcip == INADDR_ANY)
    {
      if ((uint32_t) -1 == (srcip = libnet_get_ipaddr4 (libnet)))
        {
          g_warning ("%s: Unable to get the IPv4 address of default "
                     "interface %s: %s. Address '%s' will be skipped.",
                     __func__, ifname, libnet_geterror (libnet), target);
          g_free (target);
          g_free (ifname);
          return;
        }
    }

  g_debug ("%s: Ping %s   Interface: %s   Src IP: %s   Src MAC: %s", __func__,
           dst_str, ifname, libnet_addr2name4 (libnet_get_ipaddr4 (libnet), 0),
           format_mac (srcmac, mac_debug_buf, sizeof (mac_debug_buf)));

  pingip_send ();
  libnet_clear_packet (libnet);

  g_free (target);
  g_free (ifname);
}
