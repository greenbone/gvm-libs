/* OpenVAS: openvas-libraries/base
 * $Id$
 * Description: API (structs and protos) for Access Rules
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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
 * @file accessrules.h
 * @brief Protos and data structures for Access Rules data sets.
 *
 * This file contains the protos for \ref accessrules.c
 */

#ifndef _OPENVAS_ACCESSRULES_H
#define _OPENVAS_ACCESSRULES_H

#include <glib.h>

/**
 * @brief The possible types of a rule.
 */
typedef enum {
  ALLOW = 1,  ///< allow a corresponding IP
  REJECT = 2  ///< reject a corresponding IP
} rule_t;

/**
 * @brief The structure for a Access Rule.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
typedef struct accessrule
{
  rule_t rule;      ///< Rule type
  gchar * ip;       ///< hostname, IP or IP with netmask. This is also used as
                    ///< unique key for collections of access rules
  gchar * comment;  ///< Comment for this access rule
} accessrule_t;

accessrule_t *accessrule_new (void);
void accessrule_free (accessrule_t *);

rule_t accessrule_rule (const accessrule_t *);
gchar *accessrule_ip (const accessrule_t *);
gchar *accessrule_comment (const accessrule_t *);

int accessrule_set_rule (accessrule_t *, const rule_t);
int accessrule_set_ip (accessrule_t *, const gchar *);
int accessrule_set_comment (accessrule_t *, const gchar *);

gchar *accessrule_as_xml (const accessrule_t *);

/* Collections of Access Rules. */

/**
 * @brief A collection of information records corresponding to Access Rules.
 */
typedef GHashTable accessrules_t;

accessrules_t *accessrules_new ();
void accessrules_free (accessrules_t *);
guint accessrules_size (accessrules_t *);
void accessrules_add (accessrules_t *, accessrule_t *);

guint accessrules_to_file (accessrules_t *, gchar *);
accessrules_t * accessrules_from_file (gchar *);

#endif /* not _OPENVAS_ACCESSRULE_H */
