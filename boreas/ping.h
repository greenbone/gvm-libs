/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _GVM_BOREAS_PING_H
#define _GVM_BOREAS_PING_H

#include <glib.h>

void send_icmp (gpointer, gpointer, gpointer);

void send_tcp (gpointer, gpointer, gpointer);

void send_arp (gpointer, gpointer, gpointer);

#endif /* not _GVM_BOREAS_PING_H */
