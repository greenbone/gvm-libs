/* OpenVAS
 * $Id$
 * Description: Header file for module kb.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_KB_H
#define OPENVAS_KB_H

/* this define can be removed, once openvas-plugins 1.0.5 is mandatory
   minimum version */
#define NEW_KB_MGMT

#define KB_TYPE_INT ARG_INT
#define KB_TYPE_STR ARG_STRING

struct kb_item {
	char * name;
 	char type;
	union {
		char * v_str;
		int v_int;
	} v;
	struct kb_item * next;
};

struct kb_item ** kb_new();
struct kb_item * kb_item_get_single(struct kb_item **, char *, int );
char * kb_item_get_str(struct kb_item **, char *);
int    kb_item_get_int(struct kb_item **, char *);
struct kb_item * kb_item_get_all(struct kb_item **, char *);
struct kb_item * kb_item_get_pattern(struct kb_item **, char *);
void   kb_item_get_all_free(struct kb_item *);

int    kb_item_add_str(struct kb_item **, char *, char *);
int    kb_item_set_str(struct kb_item **, char *, char *);
int    kb_item_add_int(struct kb_item **, char *, int   );
int    kb_item_set_int(struct kb_item **, char *, int   );
void   kb_item_rm_all(struct kb_item **, char *);

struct arglist * plug_get_oldstyle_kb(struct arglist * );

#endif
