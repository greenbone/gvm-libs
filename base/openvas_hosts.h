/* openvas-libraries/base
 * $Id$
 * Description: API (structs and protos) for Hosts objects
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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
 * @file hosts.h
 * @brief Protos and data structures for Hosts collections and single hosts
 * objects.
 *
 * This file contains the protos for \ref hosts.c
 */

#ifndef _OPENVAS_HOSTS_H
#define _OPENVAS_HOSTS_H

#include "openvas_networking.h"

#include <glib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Static values */

enum host_type {
  HOST_TYPE_NAME = 0,       /* Hostname eg. foo */
  HOST_TYPE_IPV4,           /* eg. 192.168.1.1 */
  HOST_TYPE_CIDR_BLOCK,     /* eg. 192.168.15.0/24 */
  HOST_TYPE_RANGE_SHORT,    /* eg. 192.168.15.10-20 */
  HOST_TYPE_RANGE_LONG,     /* eg. 192.168.15.10-192.168.18.3 */
  HOST_TYPE_IPV6,           /* eg. ::1 */
  HOST_TYPE_CIDR6_BLOCK,    /* eg. ::ffee/120 */
  HOST_TYPE_RANGE6_LONG,    /* eg. ::1:200:7-::1:205:500 */
  HOST_TYPE_RANGE6_SHORT,   /* eg. ::1-fe10 */
  HOST_TYPE_MAX             /* Boundary checking. */
};

/* Typedefs */
typedef struct openvas_host openvas_host_t;
typedef struct openvas_hosts openvas_hosts_t;

/* Data structures. */

/**
 * @brief The structure for a single host object.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
struct openvas_host
{
  union {
    gchar *name;            /* Hostname. */
    struct in_addr addr;    /* IPv4 address */
    struct in6_addr addr6;  /* IPv6 address */
  };
  enum host_type type;  /* HOST_TYPE_NAME, HOST_TYPE_IPV4 or HOST_TYPE_IPV6. */
};

/**
 * @brief The structure for Hosts collection.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
struct openvas_hosts
{
  gchar *orig_str;          /* Original hosts definition string. */
  GList *hosts;             /* Hosts objects list. */
  GList *current;           /* Current host object in iteration. */
  unsigned int count;       /* Number of single host objects in hosts list. */
  unsigned int removed;     /* Number of duplicate/excluded values. */
};

/* Function prototypes. */

 /* openvas_hosts_t related */
openvas_hosts_t *
openvas_hosts_new (const gchar *);

openvas_hosts_t *
openvas_hosts_new_with_max (const gchar *, unsigned int);

openvas_host_t *
openvas_hosts_next (openvas_hosts_t *);

void
openvas_hosts_free (openvas_hosts_t *);

void
openvas_hosts_shuffle (openvas_hosts_t *);

void
openvas_hosts_reverse (openvas_hosts_t *);

void
openvas_hosts_resolve (openvas_hosts_t *);

int
openvas_hosts_exclude (openvas_hosts_t *, const gchar *, int);

int
openvas_hosts_reverse_lookup_only (openvas_hosts_t *);

int
openvas_hosts_reverse_lookup_unify (openvas_hosts_t *);

unsigned int
openvas_hosts_count (const openvas_hosts_t *);

unsigned int
openvas_hosts_removed (const openvas_hosts_t *);

 /* openvas_host_t related */

int
openvas_host_in_hosts (const openvas_host_t *, const struct in6_addr *,
                       const openvas_hosts_t *);

gchar *
openvas_host_type_str (const openvas_host_t *);

int
openvas_host_type (const openvas_host_t *);

gchar *
openvas_host_value_str (const openvas_host_t *);

int
openvas_host_resolve (const openvas_host_t *, void *, int);

int
openvas_host_get_addr6 (const openvas_host_t *, struct in6_addr *);

#endif /* not _OPENVAS_HOSTS_H */
