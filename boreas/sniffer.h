/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BOREAS_SNIFFER_H
#define BOREAS_SNIFFER_H

#include "alivedetection.h"

#include <pcap.h>

int
start_sniffer_thread (scanner_t *, pthread_t *);

int
stop_sniffer_thread (scanner_t *, pthread_t);

#endif /* not BOREAS_SNIFFER_H */
