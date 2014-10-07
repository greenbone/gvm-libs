/* openvase-libraries/omp/xml
 * $Id$
 * Description: Simple XML reader.
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

/**
 * @file xml.c
 * @brief Simple XML reader.
 *
 * This is a generic XML interface.  The key function is \ref read_entity.
 *
 * The openvas-manager tests use this interface to read and handle the XML
 * returned by the manager.  The OMP part of openvas-client does the same.
 *
 * There are examples of using this interface in omp.c and in the
 * openvas-manager tests.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xml.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib   xml"

/**
 * @brief Size of the buffer for reading from the manager.
 */
#define BUFFER_SIZE 1048576

/**
 * @brief XML context.
 *
 * This structure is used to pass data between XML event handlers and the
 * caller of the XML parser.
 */
typedef struct
{
  GSList *first;                ///< The name of the very first entity.
  GSList *current;              ///< The element currently being parsed.
  gboolean done;                ///< Flag which is true when the first element is closed.
} context_data_t;

/**
 * @brief Create an entity.
 *
 * @param[in]  name  Name of the entity.  Copied, freed by free_entity.
 * @param[in]  text  Text of the entity.  Copied, freed by free_entity.
 *
 * @return A newly allocated entity.
 */
entity_t
make_entity (const char *name, const char *text)
{
  entity_t entity;
  entity = g_malloc (sizeof (*entity));
  entity->name = g_strdup (name ? : "");
  entity->text = g_strdup (text ? : "");
  entity->entities = NULL;
  entity->attributes = NULL;
  return entity;
}

/**
 * @brief Return all the entities from an entities_t after the first.
 *
 * @param[in]  entities  The list of entities.
 *
 * @return All the entities that follow the first.
 */
entities_t
next_entities (entities_t entities)
{
  if (entities)
    return (entities_t) entities->next;
  return NULL;
}

/**
 * @brief Return the first entity from an entities_t.
 *
 * @param[in]  entities  The list of entities.
 *
 * @return The first entity.
 */
entity_t
first_entity (entities_t entities)
{
  if (entities)
    return (entity_t) entities->data;
  return NULL;
}

/**
 * @brief Add an XML entity to a tree of entities.
 *
 * @param[in]  entities  The tree of entities
 * @param[in]  name      Name of the entity.  Copied, copy is freed by
 *                       free_entity.
 * @param[in]  text      Text of the entity.  Copied, copy is freed by
 *                       free_entity.
 *
 * @return The new entity.
 */
entity_t
add_entity (entities_t * entities, const char *name, const char *text)
{
  entity_t entity = make_entity (name, text);
  if (entities)
    *entities = g_slist_append (entities ? *entities : NULL, entity);
  return entity;
}

/**
 * @brief Free an entity, recursively.
 *
 * @param[in]  entity  The entity, can be NULL.
 */
void
free_entity (entity_t entity)
{
  if (entity)
    {
      free (entity->name);
      free (entity->text);
      if (entity->attributes)
        g_hash_table_destroy (entity->attributes);
      if (entity->entities)
        {
          GSList *list = entity->entities;
          while (list)
            {
              free_entity (list->data);
              list = list->next;
            }
          g_slist_free (entity->entities);
        }
      free (entity);
    }
}

/**
 * @brief Get the text an entity.
 *
 * @param[in]  entity  Entity.
 *
 * @return Entity text, which is freed by free_entity.
 */
char *
entity_text (entity_t entity)
{
  return entity->text;
}

/**
 * @brief Get the name an entity.
 *
 * @param[in]  entity  Entity.
 *
 * @return Entity name, which is freed by free_entity.
 */
char *
entity_name (entity_t entity)
{
  return entity->name;
}

/**
 * @brief Compare a given name with the name of a given entity.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name.
 *
 * @return Zero if entity name matches name, otherwise a positive or negative
 *         number as from strcmp.
 */
int
compare_entity_with_name (gconstpointer entity, gconstpointer name)
{
  return strcmp (entity_name ((entity_t) entity), (char *) name);
}

/**
 * @brief Get a child of an entity.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name of the child.
 *
 * @return Entity if found, else NULL.
 */
entity_t
entity_child (entity_t entity, const char *name)
{
  if (entity->entities)
    {
      entities_t match = g_slist_find_custom (entity->entities,
                                              name,
                                              compare_entity_with_name);
      return match ? (entity_t) match->data : NULL;
    }
  return NULL;
}

/**
 * @brief Get an attribute of an entity.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name of the attribute.
 *
 * @return Attribute if found, else NULL.
 */
const char *
entity_attribute (entity_t entity, const char *name)
{
  if (entity->attributes)
    return (const char *) g_hash_table_lookup (entity->attributes, name);
  return NULL;
}

/**
 * @brief Add attributes from an XML callback to an entity.
 *
 * @param[in]  entity  The entity.
 * @param[in]  names   List of attribute names.
 * @param[in]  values  List of attribute values.
 */
void
add_attributes (entity_t entity, const gchar ** names, const gchar ** values)
{
  if (*names && *values)
    {
      if (entity->attributes == NULL)
        entity->attributes =
          g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
      while (*names && *values)
        {
          if (*values)
            g_hash_table_insert (entity->attributes, g_strdup (*names),
                                 g_strdup (*values));
          names++;
          values++;
        }
    }
}

/**
 * @brief Handle the start of an OMP XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  attribute_names   XML attribute name.
 * @param[in]  attribute_values  XML attribute values.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
handle_start_element (GMarkupParseContext * context, const gchar * element_name,
                      const gchar ** attribute_names,
                      const gchar ** attribute_values, gpointer user_data,
                      GError ** error)
{
  entity_t entity;
  context_data_t *data = (context_data_t *) user_data;
  if (data->current)
    {
      entity_t current = (entity_t) data->current->data;
      entity = add_entity (&current->entities, element_name, NULL);
    }
  else
    entity = add_entity (NULL, element_name, NULL);

  add_attributes (entity, attribute_names, attribute_values);

  /* "Push" the element. */
  if (data->first == NULL)
    data->current = data->first = g_slist_prepend (NULL, entity);
  else
    data->current = g_slist_prepend (data->current, entity);
}

/**
 * @brief Handle the end of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
handle_end_element (GMarkupParseContext * context, const gchar * element_name,
                    gpointer user_data, GError ** error)
{
  context_data_t *data = (context_data_t *) user_data;
  assert (data->current && data->first);
  if (data->current == data->first)
    {
      assert (strcmp (element_name,
                      /* The name of the very first entity. */
                      ((entity_t) (data->first->data))->name) == 0);
      data->done = TRUE;
      /* "Pop" the element. */
      data->current = g_slist_next (data->current);
    }
  else if (data->current)
    {
      GSList *front;
      /* "Pop" and free the element. */
      front = data->current;
      data->current = g_slist_next (data->current);
      g_slist_free_1 (front);
    }
}

/**
 * @brief Handle additional text of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
handle_text (GMarkupParseContext * context, const gchar * text, gsize text_len,
             gpointer user_data, GError ** error)
{
  context_data_t *data = (context_data_t *) user_data;
  entity_t current = (entity_t) data->current->data;
  if (current->text)
    {
      gchar *old = current->text;
      current->text = g_strconcat (current->text, text, NULL);
      g_free (old);
    }
  else
    current->text = g_strdup (text);
}

/**
 * @brief Handle an OMP XML parsing error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
void
handle_error (GMarkupParseContext * context, GError * error, gpointer user_data)
{
  g_message ("   Error: %s\n", error->message);
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   timeout   Server idle time before giving up, in seconds.  0 to
 *                        wait forever.
 * @param[out]  entity    Pointer to an entity tree.
 * @param[out]  string    An optional return location for the text read
 *                        from the session.  If NULL then it simply
 *                        remains NULL.  If a pointer to NULL then it points
 *                        to a freshly allocated GString on successful return.
 *                        Otherwise it points to an existing GString onto
 *                        which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout.
 */
int
try_read_entity_and_string (gnutls_session_t * session, int timeout,
                            entity_t * entity, GString ** string_return)
{
  GMarkupParser xml_parser;
  GError *error = NULL;
  GMarkupParseContext *xml_context;
  GString *string;
  int socket;
  time_t last_time;

  // Buffer for reading from the manager.
  char buffer_start[BUFFER_SIZE];
  // End of the manager reading buffer.
  char *buffer_end = buffer_start + BUFFER_SIZE;

  /* Record the start time. */

  if (time (&last_time) == -1)
    {
      g_warning ("   failed to get current time: %s\n",
                 strerror (errno));
      return -1;
    }

  if (timeout > 0)
    {
      /* Turn off blocking. */

      socket = GPOINTER_TO_INT (gnutls_transport_get_ptr (*session));
      if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1)
        return -1;
    }
  else
    /* Quiet compiler. */
    socket = 0;

  /* Setup return arg. */

  if (string_return == NULL)
    string = NULL;
  else if (*string_return == NULL)
    string = g_string_new ("");
  else
    string = *string_return;

  /* Create the XML parser. */

  xml_parser.start_element = handle_start_element;
  xml_parser.end_element = handle_end_element;
  xml_parser.text = handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = handle_error;

  context_data_t context_data;
  context_data.done = FALSE;
  context_data.first = NULL;
  context_data.current = NULL;

  /* Setup the XML context. */

  xml_context =
    g_markup_parse_context_new (&xml_parser, 0, &context_data, NULL);

  /* Read and parse, until encountering end of file or error. */

  while (1)
    {
      ssize_t count;
      while (1)
        {
          g_debug ("   asking for %i\n", (int) (buffer_end - buffer_start));
          count =
            gnutls_record_recv (*session, buffer_start,
                                buffer_end - buffer_start);
          if (count < 0)
            {
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try read again. */
                continue;
              if ((timeout > 0) && (count == GNUTLS_E_AGAIN))
                {
                  /* Server still busy, either timeout and try read again. */
                  if ((timeout - (time (NULL) - last_time))
                      <= 0)
                    {
                      g_warning ("   timeout\n");
                      fcntl (socket, F_SETFL, 0L);
                      g_markup_parse_context_free (xml_context);
                      return -4;
                    }
                  continue;
                }
              if (count == GNUTLS_E_REHANDSHAKE)
                /* Try again. TODO Rehandshake. */
                continue;
              if (context_data.first && context_data.first->data)
                {
                  free_entity (context_data.first->data);
                  g_slist_free_1 (context_data.first);
                }
              if (string && *string_return == NULL)
                g_string_free (string, TRUE);
              if (timeout > 0)
                fcntl (socket, F_SETFL, 0L);
              g_markup_parse_context_free (xml_context);
              return -1;
            }
          if (count == 0)
            {
              /* End of file. */
              g_markup_parse_context_end_parse (xml_context, &error);
              if (error)
                {
                  g_warning ("   End error: %s\n", error->message);
                  g_error_free (error);
                }
              if (context_data.first && context_data.first->data)
                {
                  free_entity (context_data.first->data);
                  g_slist_free_1 (context_data.first);
                }
              if (string && *string_return == NULL)
                g_string_free (string, TRUE);
              if (timeout > 0)
                fcntl (socket, F_SETFL, 0L);
              g_markup_parse_context_free (xml_context);
              return -3;
            }
          break;
        }

      g_debug ("<= %.*s\n", (int) count, buffer_start);

      if (string)
        g_string_append_len (string, buffer_start, count);

      g_markup_parse_context_parse (xml_context, buffer_start, count, &error);
      if (error)
        {
          g_error_free (error);
          if (context_data.first && context_data.first->data)
            {
              free_entity (context_data.first->data);
              g_slist_free_1 (context_data.first);
            }
          if (string && *string_return == NULL)
            g_string_free (string, TRUE);
          if (timeout > 0)
            fcntl (socket, F_SETFL, 0L);
          g_markup_parse_context_free (xml_context);
          return -2;
        }
      if (context_data.done)
        {
          g_markup_parse_context_end_parse (xml_context, &error);
          if (error)
            {
              g_warning ("   End error: %s\n", error->message);
              g_error_free (error);
              if (context_data.first && context_data.first->data)
                {
                  free_entity (context_data.first->data);
                  g_slist_free_1 (context_data.first);
                }
              if (timeout > 0)
                fcntl (socket, F_SETFL, 0L);
              g_markup_parse_context_free (xml_context);
              return -2;
            }
          *entity = (entity_t) context_data.first->data;
          if (string)
            *string_return = string;
          if (timeout > 0)
            fcntl (socket, F_SETFL, 0L);
          g_markup_parse_context_free (xml_context);
          return 0;
        }

      if ((timeout > 0) && (time (&last_time) == -1))
        {
          g_warning ("   failed to get current time (1): %s\n",
                     strerror (errno));
          fcntl (socket, F_SETFL, 0L);
          g_markup_parse_context_free (xml_context);
          return -1;
        }
    }
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   timeout   Seconds or server idle time before giving up.  0 to
 *                        wait forever.
 * @param[out]  entity    Pointer to an entity tree.
 * @param[out]  string    An optional return location for the text read
 *                        from the session.  If NULL then it simply
 *                        remains NULL.  If a pointer to NULL then it points
 *                        to a freshly allocated GString on successful return.
 *                        Otherwise it points to an existing GString onto
 *                        which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout.
 */
int
read_entity_and_string (gnutls_session_t * session, entity_t * entity,
                        GString ** string_return)
{
  return try_read_entity_and_string (session, 0, entity, string_return);
}

/**
 * @brief Read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[out]  entity    Pointer to an entity tree.
 * @param[out]  text      A pointer to a pointer, at which to store the
 *                        address of a newly allocated string holding the
 *                        text read from the session, if the text is required,
 *                        else NULL.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity_and_text (gnutls_session_t * session, entity_t * entity,
                      char **text)
{
  if (text)
    {
      GString *string = NULL;
      int ret = read_entity_and_string (session, entity, &string);
      if (ret)
        {
          if (string)
            g_string_free (string, TRUE);
          return ret;
        }
      *text = g_string_free (string, FALSE);
      return 0;
    }
  return read_entity_and_string (session, entity, NULL);
}


/**
 * @brief Read entity and text. Free the entity immediately.
 *
 * @param[in]   session  Pointer to GNUTLS session to read from.
 * @param[out]  string   Return location for the string.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_string (gnutls_session_t * session, GString ** string)
{
  int ret = 0;
  entity_t entity;

  if (!(ret = read_entity_and_string (session, &entity, string)))
    free_entity (entity);

  return ret;
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   timeout   Server idle time before giving up, in seconds.  0 to
 *                        wait forever.
 * @param[out]  entity    Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
try_read_entity (gnutls_session_t * session, int timeout, entity_t * entity)
{
  return try_read_entity_and_string (session, timeout, entity, NULL);
}

/**
 * @brief Read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[out]  entity    Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity (gnutls_session_t * session, entity_t * entity)
{
  return try_read_entity (session, 0, entity);
}

/**
 * @brief Read an XML entity tree from a string.
 *
 * @param[in]   string  Input string.
 * @param[out]  entity  Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 XML ended prematurely.
 */
int
parse_entity (const char *string, entity_t * entity)
{
  GMarkupParser xml_parser;
  GError *error = NULL;
  GMarkupParseContext *xml_context;
  context_data_t context_data;

  /* Create the XML parser. */

  xml_parser.start_element = handle_start_element;
  xml_parser.end_element = handle_end_element;
  xml_parser.text = handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = handle_error;

  context_data.done = FALSE;
  context_data.first = NULL;
  context_data.current = NULL;

  /* Setup the XML context. */

  xml_context =
    g_markup_parse_context_new (&xml_parser, 0, &context_data, NULL);

  /* Parse the string. */

  g_markup_parse_context_parse (xml_context, string, strlen (string), &error);
  if (error)
    {
      g_error_free (error);
      if (context_data.first && context_data.first->data)
        {
          free_entity (context_data.first->data);
          g_slist_free_1 (context_data.first);
        }
      return -2;
    }
  if (context_data.done)
    {
      g_markup_parse_context_end_parse (xml_context, &error);
      if (error)
        {
          g_warning ("   End error: %s\n", error->message);
          g_error_free (error);
          if (context_data.first && context_data.first->data)
            {
              free_entity (context_data.first->data);
              g_slist_free_1 (context_data.first);
            }
          return -2;
        }
      *entity = (entity_t) context_data.first->data;
      g_slist_free_1 (context_data.first);
      return 0;
    }
  if (context_data.first && context_data.first->data)
    {
      free_entity (context_data.first->data);
      g_slist_free_1 (context_data.first);
    }
  return -3;
}

/**
 * @brief Print an XML entity for g_slist_foreach to a GString.
 *
 * @param[in]  entity  The entity, as a gpointer.
 * @param[in]  string  The stream to which to print, as a gpointer.
 */
static void
foreach_print_entity_to_string (gpointer entity, gpointer string)
{
  print_entity_to_string ((entity_t) entity, (GString *) string);
}

/**
 * @brief Print an XML attribute for g_hash_table_foreach to a GString.
 *
 * @param[in]  name    The attribute name.
 * @param[in]  value   The attribute value.
 * @param[in]  string  The string to which to print.
 */
static void
foreach_print_attribute_to_string (gpointer name, gpointer value,
                                   gpointer string)
{
  g_string_append_printf ((GString *) string, " %s=\"%s\"", (char *) name,
                          (char *) value);
}

/**
 * @brief Print an XML entity tree to a GString, appending it if string is not
 * @brief empty.
 *
 * @param[in]      entity  Entity tree to print to string.
 * @param[in,out]  string  String to write to (will be created if NULL).
 */
void
print_entity_to_string (entity_t entity, GString * string)
{
  gchar *text_escaped = NULL;
  g_string_append_printf (string, "<%s", entity->name);
  if (entity->attributes && g_hash_table_size (entity->attributes))
    g_hash_table_foreach (entity->attributes, foreach_print_attribute_to_string,
                          string);
  g_string_append_printf (string, ">");
  text_escaped = g_markup_escape_text (entity->text, -1);
  g_string_append_printf (string, "%s", text_escaped);
  g_free (text_escaped);
  g_slist_foreach (entity->entities, foreach_print_entity_to_string, string);
  g_string_append_printf (string, "</%s>", entity->name);
}

/**
 * @brief Print an XML entity for g_slist_foreach.
 *
 * @param[in]  entity  The entity, as a gpointer.
 * @param[in]  stream  The stream to which to print, as a gpointer.
 */
static void
foreach_print_entity (gpointer entity, gpointer stream)
{
  print_entity ((FILE *) stream, (entity_t) entity);
}

/**
 * @brief Print an XML attribute for g_hash_table_foreach.
 *
 * @param[in]  name    The attribute name.
 * @param[in]  value   The attribute value.
 * @param[in]  stream  The stream to which to print.
 */
static void
foreach_print_attribute (gpointer name, gpointer value, gpointer stream)
{
  fprintf ((FILE *) stream, " %s=\"%s\"", (char *) name, (char *) value);
}

/**
 * @brief Print an XML entity.
 *
 * @param[in]  entity  The entity.
 * @param[in]  stream  The stream to which to print.
 */
void
print_entity (FILE * stream, entity_t entity)
{
  gchar *text_escaped = NULL;
  fprintf (stream, "<%s", entity->name);
  if (entity->attributes && g_hash_table_size (entity->attributes))
    g_hash_table_foreach (entity->attributes, foreach_print_attribute, stream);
  fprintf (stream, ">");
  text_escaped = g_markup_escape_text (entity->text, -1);
  fprintf (stream, "%s", text_escaped);
  g_free (text_escaped);
  g_slist_foreach (entity->entities, foreach_print_entity, stream);
  fprintf (stream, "</%s>", entity->name);
  fflush (stream);
}

/* "Formatted" (indented) output of entity_t */

/**
 * @brief Print an XML attribute for g_hash_table_foreach to stdout.
 *
 * @param[in]  name    The attribute name.
 * @param[in]  value   The attribute value.
 * @param[in]  none    (ignored).
 */
static void
foreach_print_attribute_format (gpointer name, gpointer value, gpointer none)
{
  printf (" %s=\"%s\"", (char *) name, (char *) value);
}

/**
 * @brief Print an XML entity to stdout, recusively printing its children.
 * @brief Does very basic indentation for pretty printing.
 *
 * This function is used as the (callback) GFunc in g_slist_foreach.
 *
 * @param[in]  entity  The entity.
 * @param[in]  indent  Indentation level, indentation width is 2 spaces.
 *                     Use GINT_TO_POINTER to convert a integer value when
 *                     passing this parameter.
 */
void
print_entity_format (entity_t entity, gpointer indent)
{
  int i = 0;
  int indentation = GPOINTER_TO_INT (indent);
  gchar *text_escaped = NULL;

  for (i = 0; i < indentation; i++)
    printf ("  ");

  printf ("<%s", entity->name);
  if (entity->attributes && g_hash_table_size (entity->attributes))
    g_hash_table_foreach (entity->attributes, foreach_print_attribute_format,
                          indent);
  printf (">");

  text_escaped = g_markup_escape_text (entity->text, -1);
  printf ("%s", text_escaped);
  g_free (text_escaped);

  if (entity->entities)
    {
      printf ("\n");
      g_slist_foreach (entity->entities, (GFunc) print_entity_format,
                       GINT_TO_POINTER (indentation + 1));
      for (i = 0; i < indentation; i++)
        printf ("  ");
    }

  printf ("</%s>\n", entity->name);
}

/**
 * @brief Look for a key-value pair in a hash table.
 *
 * @param[in]  key          Key.
 * @param[in]  value        Value.
 * @param[in]  attributes2  The hash table.
 *
 * @return FALSE if found, TRUE otherwise.
 */
gboolean
compare_find_attribute (gpointer key, gpointer value, gpointer attributes2)
{
  gchar *value2 = g_hash_table_lookup (attributes2, key);
  if (value2 && strcmp (value, value2) == 0)
    return FALSE;
  g_debug ("  compare failed attribute: %s\n", (char *) value);
  return TRUE;
}

/**
 * @brief Compare two XML entity.
 *
 * @param[in]  entity1  First entity.
 * @param[in]  entity2  First entity.
 *
 * @return 0 if equal, 1 otherwise.
 */
int
compare_entities (entity_t entity1, entity_t entity2)
{
  if (entity1 == NULL)
    return entity2 == NULL ? 0 : 1;
  if (entity2 == NULL)
    return 1;

  if (strcmp (entity1->name, entity2->name))
    {
      g_debug ("  compare failed name: %s vs %s\n", entity1->name,
                 entity2->name);
      return 1;
    }
  if (strcmp (entity1->text, entity2->text))
    {
      g_debug ("  compare failed text %s vs %s (%s)\n", entity1->text,
                 entity2->text, entity1->name);
      return 1;
    }

  if (entity1->attributes == NULL)
    {
      if (entity2->attributes)
        return 1;
    }
  else
    {
      if (entity2->attributes == NULL)
        return 1;
      if (g_hash_table_find
          (entity1->attributes, compare_find_attribute,
           (gpointer) entity2->attributes))
        {
          g_debug ("  compare failed attributes\n");
          return 1;
        }
    }

  // FIX entities can be in any order
  GSList *list1 = entity1->entities;
  GSList *list2 = entity2->entities;
  while (list1 && list2)
    {
      if (compare_entities (list1->data, list2->data))
        {
          g_debug ("  compare failed subentity\n");
          return 1;
        }
      list1 = g_slist_next (list1);
      list2 = g_slist_next (list2);
    }
  if (list1 == list2)
    return 0;
  /* More entities in one of the two. */
  g_debug ("  compare failed number of entities (%s)\n", entity1->name);
  return 1;
}

/**
 * @brief Count the number of entities.
 *
 * @param[in]  entities  Entities.
 *
 * @return Number of entities.
 */
int
xml_count_entities (entities_t entities)
{
  int count = 0;
  while (first_entity (entities))
    {
      entities = next_entities (entities);
      count++;
    }
  return count;
}

/**
 * @brief Append formatted escaped XML to a string.
 *
 * @param[in]  xml     XML string.
 * @param[in]  format  Format string.
 * @param[in]  ...     Arguments for format string.
 *
 * @return Result of XSL transformation.
 */
void
xml_string_append (GString *xml, const char *format, ...)
{
  gchar *piece;
  va_list args;

  va_start (args, format);
  piece = g_markup_vprintf_escaped (format, args);
  va_end (args);
  g_string_append (xml, piece);
  g_free (piece);
}
