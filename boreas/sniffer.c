/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
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

#include "sniffer.h"

#include <glib.h>
#include <stdlib.h>

/**
 * @brief open a new pcap handle ad set provided filter.
 *
 * @param iface interface to use.
 * @param filter pcap filter to use.
 *
 * @return pcap_t handle or NULL on error
 */
pcap_t *
open_live (char *iface, char *filter)
{
  /* iface considerations:
   * pcap_open_live(iface, ...) sniffs on all interfaces(linux) if iface
   * argument is NULL pcap_lookupnet(iface, ...) is used to set ipv4 network
   * number and mask associated with iface pcap_compile(..., mask) netmask
   * specifies the IPv4 netmask of the network on which packets are being
   * captured; it is used only when checking for IPv4 broadcast addresses in the
   * filter program
   *
   *  If we are not checking for IPv4 broadcast addresses in the filter program
   * we do not need an iface (if we also want to listen on all interface) and we
   * do not need to call pcap_lookupnet
   */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle;
  struct bpf_program filter_prog;

  /* iface, snapshot length of handle, promiscuous mode, packet buffer timeout
   * (ms), errbuff */
  errbuf[0] = '\0';
  pcap_handle = pcap_open_live (iface, 1500, 0, 100, errbuf);
  if (pcap_handle == NULL)
    {
      g_warning ("%s: %s", __func__, errbuf);
      return NULL;
    }
  if (g_utf8_strlen (errbuf, -1) != 0)
    {
      g_warning ("%s: %s", __func__, errbuf);
    }

  /* handle, struct bpf_program *fp, int optimize, bpf_u_int32 netmask */
  if (pcap_compile (pcap_handle, &filter_prog, filter, 1, PCAP_NETMASK_UNKNOWN)
      < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_warning ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }

  if (pcap_setfilter (pcap_handle, &filter_prog) < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_warning ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }
  pcap_freecode (&filter_prog);

  return pcap_handle;
}
