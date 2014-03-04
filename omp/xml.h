/* openvase-libraries/omp/xml
 * $Id$
 * Description: Headers for simple XML reader.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
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

#ifndef _OPENVAS_LIBRARIES_XML_H
#define _OPENVAS_LIBRARIES_XML_H

#include <glib.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif

typedef GSList *entities_t;

/**
 * @brief XML element.
 */
struct entity_s
{
  char *name;                   ///< Name.
  char *text;                   ///< Text.
  GHashTable *attributes;       ///< Attributes.
  entities_t entities;          ///< Children.
};
typedef struct entity_s *entity_t;

entities_t next_entities (entities_t);

entity_t first_entity (entities_t);

entity_t add_entity (entities_t *, const char *, const char *);

int compare_entities (entity_t, entity_t);

entity_t entity_child (entity_t, const char *);

const char *entity_attribute (entity_t, const char *);

char *entity_name (entity_t entity);

char *entity_text (entity_t entity);

void free_entity (entity_t);

void print_entity (FILE *, entity_t);

void print_entity_format (entity_t, gpointer indentation);

int try_read_entity_and_string (gnutls_session_t *, int, entity_t *,
                                GString **);

int read_entity_and_string (gnutls_session_t *, entity_t *, GString **);

int read_entity_and_text (gnutls_session_t *, entity_t *, char **);

int try_read_entity (gnutls_session_t *, int, entity_t *);

int read_entity (gnutls_session_t *, entity_t *);

int read_string (gnutls_session_t *, GString **);

int parse_entity (const char *, entity_t *);

void print_entity_to_string (entity_t entity, GString * string);

int xml_count_entities (entities_t);

void xml_string_append (GString *, const char *, ...);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* not _OPENVAS_LIBRARIES_XML_H */
