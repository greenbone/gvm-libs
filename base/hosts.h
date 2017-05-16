/* gvm-lib/base
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
 * @file hosts.h
 * @brief Protos and data structures for Hosts collections and single hosts
 * objects.
 *
 * This file contains the protos for \ref hosts.c
 */

#ifndef _GVM_HOSTS_H
#define _GVM_HOSTS_H

#include <glib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "networking.h"

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
typedef struct gvm_host gvm_host_t;
typedef struct gvm_hosts gvm_hosts_t;

/* Data structures. */

/**
 * @brief The structure for a single host object.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
struct gvm_host
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
struct gvm_hosts
{
  gchar *orig_str;          /* Original hosts definition string. */
  GList *hosts;             /* Hosts objects list. */
  GList *current;           /* Current host object in iteration. */
  unsigned int count;       /* Number of single host objects in hosts list. */
  unsigned int removed;     /* Number of duplicate/excluded values. */
};

/* Function prototypes. */

 /* gvm_hosts_t related */
gvm_hosts_t *
gvm_hosts_new (const gchar *);

gvm_hosts_t *
gvm_hosts_new_with_max (const gchar *, unsigned int);

gvm_host_t *
gvm_hosts_next (gvm_hosts_t *);

void
gvm_hosts_free (gvm_hosts_t *);

void
gvm_hosts_shuffle (gvm_hosts_t *);

void
gvm_hosts_reverse (gvm_hosts_t *);

void
gvm_hosts_resolve (gvm_hosts_t *);

int
gvm_hosts_exclude (gvm_hosts_t *, const gchar *, int);

int
gvm_hosts_exclude_with_max (gvm_hosts_t *, const gchar *, int, unsigned int);

char *
gvm_host_reverse_lookup (gvm_host_t *);

int
gvm_hosts_reverse_lookup_only (gvm_hosts_t *);

int
gvm_hosts_reverse_lookup_unify (gvm_hosts_t *);

unsigned int
gvm_hosts_count (const gvm_hosts_t *);

unsigned int
gvm_hosts_removed (const gvm_hosts_t *);

 /* gvm_host_t related */

int
gvm_host_in_hosts (const gvm_host_t *, const struct in6_addr *,
                   const gvm_hosts_t *);

gchar *
gvm_host_type_str (const gvm_host_t *);

enum host_type
gvm_host_type (const gvm_host_t *);

gchar *
gvm_host_value_str (const gvm_host_t *);

int
gvm_host_resolve (const gvm_host_t *, void *, int);

int
gvm_host_get_addr6 (const gvm_host_t *, struct in6_addr *);

/* Miscellaneous functions */

int
gvm_get_host_type (const gchar *);

#endif /* not _GVM_HOSTS_H */
