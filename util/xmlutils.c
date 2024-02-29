/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Simple XML reader.
 *
 * This is a generic XML interface.  The key function is \ref read_entity.
 *
 * There are examples of using this interface in omp.c.
 */

#include "xmlutils.h"

#include <assert.h>      /* for assert */
#include <errno.h>       /* for errno, EAGAIN, EINTR */
#include <fcntl.h>       /* for fcntl, F_SETFL, O_NONBLOCK */
#include <glib.h>        /* for g_free, GSList, g_markup_parse_context_free */
#include <glib/gtypes.h> /* for GPOINTER_TO_INT, GINT_TO_POINTER, gsize */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h> /* for strcmp, strerror, strlen */
#include <time.h>   /* for time, time_t */
#include <unistd.h> /* for ssize_t */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

/**
 * @brief Size of the buffer for reading from the manager.
 */
#define BUFFER_SIZE 1048576

/**
 * @brief Create an entity.
 *
 * @param[in]  name  Name of the entity.  Copied, freed by free_entity.
 * @param[in]  text  Text of the entity.  Copied, freed by free_entity.
 *
 * @return A newly allocated entity.
 */
static entity_t
make_entity (const char *name, const char *text)
{
  entity_t entity;
  entity = g_malloc (sizeof (*entity));
  entity->name = g_strdup (name ? name : "");
  entity->text = g_strdup (text ? text : "");
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
add_entity (entities_t *entities, const char *name, const char *text)
{
  entity_t entity = make_entity (name, text);
  if (entities)
    *entities = g_slist_append (*entities, entity);
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
      g_free (entity->name);
      g_free (entity->text);
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
      g_free (entity);
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
  if (!entity)
    return NULL;

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
  if (!entity)
    return NULL;

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
static int
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
  if (!entity)
    return NULL;

  if (entity->entities)
    {
      entities_t match =
        g_slist_find_custom (entity->entities, name, compare_entity_with_name);
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
  if (!entity)
    return NULL;

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
static void
add_attributes (entity_t entity, const gchar **names, const gchar **values)
{
  if (names && values && *names && *values)
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
static void
ignore_start_element (GMarkupParseContext *context, const gchar *element_name,
                      const gchar **attribute_names,
                      const gchar **attribute_values, gpointer user_data,
                      GError **error)
{
  context_data_t *data = (context_data_t *) user_data;

  (void) context;
  (void) element_name;
  (void) attribute_names;
  (void) attribute_values;
  (void) error;

  data->current = GINT_TO_POINTER (GPOINTER_TO_INT (data->current) + 1);
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
static void
handle_start_element (GMarkupParseContext *context, const gchar *element_name,
                      const gchar **attribute_names,
                      const gchar **attribute_values, gpointer user_data,
                      GError **error)
{
  entity_t entity;
  context_data_t *data = (context_data_t *) user_data;

  (void) context;
  (void) error;
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
 * @brief Handle the start of an OMP XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  attribute_names   XML attribute name.
 * @param[in]  attribute_values  XML attribute values.
 */
void
xml_handle_start_element (context_data_t *context, const gchar *element_name,
                          const gchar **attribute_names,
                          const gchar **attribute_values)
{
  handle_start_element (NULL, element_name, attribute_names, attribute_values,
                        context, NULL);
}

/**
 * @brief Handle the end of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
ignore_end_element (GMarkupParseContext *context, const gchar *element_name,
                    gpointer user_data, GError **error)
{
  context_data_t *data = (context_data_t *) user_data;

  (void) context;
  (void) element_name;
  (void) error;

  data->current = GINT_TO_POINTER (GPOINTER_TO_INT (data->current) - 1);
  if (data->current == NULL)
    data->done = TRUE;
}

/**
 * @brief Handle the end of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
handle_end_element (GMarkupParseContext *context, const gchar *element_name,
                    gpointer user_data, GError **error)
{
  context_data_t *data = (context_data_t *) user_data;

  (void) context;
  (void) error;
  (void) element_name;
  assert (data->current && data->first);
  if (data->current == data->first)
    {
      assert (strcmp (element_name,
                      /* The name of the very first entity. */
                      ((entity_t) (data->first->data))->name)
              == 0);
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
 * @brief Handle the end of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 */
void
xml_handle_end_element (context_data_t *context, const gchar *element_name)
{
  handle_end_element (NULL, element_name, context, NULL);
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
static void
ignore_text (GMarkupParseContext *context, const gchar *text, gsize text_len,
             gpointer user_data, GError **error)
{
  (void) context;
  (void) text;
  (void) text_len;
  (void) user_data;
  (void) error;
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
static void
handle_text (GMarkupParseContext *context, const gchar *text, gsize text_len,
             gpointer user_data, GError **error)
{
  context_data_t *data = (context_data_t *) user_data;

  (void) context;
  (void) text_len;
  (void) error;
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
 * @brief Handle additional text of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 */
void
xml_handle_text (context_data_t *context, const gchar *text, gsize text_len)
{
  handle_text (NULL, text, text_len, context, NULL);
}

/**
 * @brief Handle an OMP XML parsing error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
static void
handle_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
  (void) context;
  (void) user_data;
  g_message ("   Error: %s\n", error->message);
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   session        Pointer to GNUTLS session.
 * @param[in]   timeout        Server idle time before giving up, in seconds.  0
 * to wait forever.
 * @param[out]  entity         Pointer to an entity tree.
 * @param[out]  string_return  An optional return location for the text read
 *                             from the session.  If NULL then it simply
 *                             remains NULL.  If a pointer to NULL then it
 * points to a freshly allocated GString on successful return. Otherwise it
 * points to an existing GString onto which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout,
 * -5 null buffer.
 */
int
try_read_entity_and_string (gnutls_session_t *session, int timeout,
                            entity_t *entity, GString **string_return)
{
  GMarkupParser xml_parser;
  GError *error = NULL;
  GMarkupParseContext *xml_context;
  GString *string;
  int socket;
  time_t last_time;

  // Buffer for reading from the manager.
  char *buffer;

  /* Record the start time. */

  if (time (&last_time) == -1)
    {
      g_warning ("   failed to get current time: %s\n", strerror (errno));
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

  buffer = g_malloc0 (BUFFER_SIZE);
  if (!buffer)
    return -5;

  /* Setup return arg. */

  if (string_return == NULL)
    string = NULL;
  else if (*string_return == NULL)
    string = g_string_new ("");
  else
    string = *string_return;

  /* Create the XML parser. */

  if (entity)
    {
      xml_parser.start_element = handle_start_element;
      xml_parser.end_element = handle_end_element;
      xml_parser.text = handle_text;
    }
  else
    {
      xml_parser.start_element = ignore_start_element;
      xml_parser.end_element = ignore_end_element;
      xml_parser.text = ignore_text;
    }
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
      int retries = 10;
      while (1)
        {
          g_debug ("   asking for %i\n", BUFFER_SIZE);
          count = gnutls_record_recv (*session, buffer, BUFFER_SIZE);
          if (count < 0)
            {
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try read again. */
                continue;
              if ((timeout > 0) && (count == GNUTLS_E_AGAIN))
                {
                  /* Server still busy, either timeout or try read again. */
                  if ((timeout - (time (NULL) - last_time)) <= 0)
                    {
                      g_warning ("   timeout\n");
                      if (fcntl (socket, F_SETFL, 0L) < 0)
                        g_warning ("%s :failed to set socket flag: %s",
                                   __func__, strerror (errno));
                      g_markup_parse_context_free (xml_context);
                      g_free (buffer);
                      return -4;
                    }
                  continue;
                }
              else if ((timeout == 0) && (count == GNUTLS_E_AGAIN))
                {
                  /* Server still busy, try read again.
                     If there is no timeout set and the server is still not
                     ready, it will try up to 10 times before closing the
                     socket.*/
                  if (retries > 0)
                    {
                      retries = retries - 1;
                      continue;
                    }
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
                {
                  if (fcntl (socket, F_SETFL, 0L) < 0)
                    g_warning ("%s :failed to set socket flag: %s", __func__,
                               strerror (errno));
                }
              g_markup_parse_context_free (xml_context);
              g_free (buffer);
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
                {
                  if (fcntl (socket, F_SETFL, 0L) < 0)
                    g_warning ("%s :failed to set socket flag: %s", __func__,
                               strerror (errno));
                }
              g_markup_parse_context_free (xml_context);
              g_free (buffer);
              return -3;
            }
          break;
        }

      g_debug ("<= %.*s\n", (int) count, buffer);

      if (string)
        g_string_append_len (string, buffer, count);

      g_markup_parse_context_parse (xml_context, buffer, count, &error);
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
            {
              if (fcntl (socket, F_SETFL, 0L) < 0)
                g_warning ("%s :failed to set socket flag: %s", __func__,
                           strerror (errno));
            }
          g_markup_parse_context_free (xml_context);
          g_free (buffer);
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
              g_free (buffer);
              return -2;
            }
          if (entity)
            *entity = (entity_t) context_data.first->data;
          if (string)
            *string_return = string;
          if (timeout > 0)
            fcntl (socket, F_SETFL, 0L);
          g_markup_parse_context_free (xml_context);
          g_free (buffer);
          return 0;
        }

      if ((timeout > 0) && (time (&last_time) == -1))
        {
          g_warning ("   failed to get current time (1): %s\n",
                     strerror (errno));
          if (fcntl (socket, F_SETFL, 0L) < 0)
            g_warning ("%s :failed to set socket flag: %s", __func__,
                       strerror (errno));
          g_markup_parse_context_free (xml_context);
          g_free (buffer);
          return -1;
        }
    }
}

/**
 * @brief Try read a response from a TLS session.
 *
 * @param[in]   session        Pointer to GNUTLS session.
 * @param[in]   timeout        Server idle time before giving up, in seconds.  0
 *                             to wait forever.
 * @param[out]  string_return  An optional return location for the text read
 *                             from the session.
 *
 * If string_return is NULL then it simply remains NULL.  If it is pointer to
 * NULL then it points to a freshly allocated GString on successful return.
 * Otherwise it must point to an existing GString onto which the text is
 * appended.
 *
 * @return 0 success, -1 read error, -4 timeout, -5 null buffer.
 */
static int
try_read_string (gnutls_session_t *session, int timeout,
                 GString **string_return)
{
  GString *string;
  int socket;
  time_t last_time;
  char *buffer; // Buffer for reading from the server.

  /* Record the start time. */

  if (time (&last_time) == -1)
    {
      g_warning ("   failed to get current time: %s\n", strerror (errno));
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

  buffer = g_malloc0 (BUFFER_SIZE);
  if (!buffer)
    return -5;

  /* Setup return arg. */

  if (string_return == NULL)
    string = NULL;
  else if (*string_return == NULL)
    string = g_string_new ("");
  else
    string = *string_return;

  /* Read until encountering end of file or error. */

  while (1)
    {
      ssize_t count;
      int retries = 10;
      while (1)
        {
          g_debug ("   asking for %i\n", BUFFER_SIZE);
          count = gnutls_record_recv (*session, buffer, BUFFER_SIZE);
          if (count < 0)
            {
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try read again. */
                continue;
              if ((timeout > 0) && (count == GNUTLS_E_AGAIN))
                {
                  /* Server still busy, either timeout or try read again. */
                  if ((timeout - (time (NULL) - last_time)) <= 0)
                    {
                      g_warning ("   timeout\n");
                      if (fcntl (socket, F_SETFL, 0L) < 0)
                        g_warning ("%s: failed to set socket flag: %s",
                                   __func__, strerror (errno));
                      g_free (buffer);
                      return -4;
                    }
                  continue;
                }
              else if ((timeout == 0) && (count == GNUTLS_E_AGAIN))
                {
                  /* Server still busy, try read again.
                   * If there is no timeout set and the server is still not
                   * ready, it will try up to 10 times before closing the
                   * socket. */
                  if (retries > 0)
                    {
                      retries = retries - 1;
                      continue;
                    }
                }

              if (count == GNUTLS_E_REHANDSHAKE)
                /* Try again. TODO Rehandshake. */
                continue;
              if (string && (*string_return == NULL))
                g_string_free (string, TRUE);
              if (timeout > 0)
                {
                  if (fcntl (socket, F_SETFL, 0L) < 0)
                    g_warning ("%s: failed to set socket flag: %s", __func__,
                               strerror (errno));
                }
              g_free (buffer);
              return -1;
            }
          if (count == 0)
            {
              /* End of file. */
              if (timeout > 0)
                {
                  if (fcntl (socket, F_SETFL, 0L) < 0)
                    g_warning ("%s :failed to set socket flag: %s", __func__,
                               strerror (errno));
                }
              if (string)
                *string_return = string;
              g_free (buffer);
              return 0;
            }
          break;
        }

      g_debug ("<= %.*s\n", (int) count, buffer);

      if (string)
        g_string_append_len (string, buffer, count);

      if ((timeout > 0) && (time (&last_time) == -1))
        {
          g_warning ("   failed to get current time (1): %s\n",
                     strerror (errno));
          if (fcntl (socket, F_SETFL, 0L) < 0)
            g_warning ("%s :failed to set socket flag: %s", __func__,
                       strerror (errno));
          g_free (buffer);
          return -1;
        }
    }
}

/**
 * @brief Try read an XML entity tree from the socket.
 *
 * @param[in]   socket         Socket to read from.
 * @param[in]   timeout        Server idle time before giving up, in seconds.  0
 *                             to wait forever.
 * @param[out]  string_return  An optional return location for the text read
 *                             from the socket.  If NULL then it simply
 *                             remains NULL.  If a pointer to NULL then it
 * points to a freshly allocated GString on successful return. Otherwise it
 * points to an existing GString onto which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout,
 * -5 null buffer.
 */
static int
try_read_string_s (int socket, int timeout, GString **string_return)
{
  GString *string;
  time_t last_time;
  /* Buffer for reading from the socket. */
  char *buffer;

  /* Record the start time. */

  if (time (&last_time) == -1)
    {
      g_warning ("   failed to get current time: %s\n", strerror (errno));
      return -1;
    }

  if (timeout > 0)
    {
      /* Turn off blocking. */

      if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1)
        return -1;
    }

  buffer = g_malloc0 (BUFFER_SIZE);
  if (!buffer)
    return -5;

  /* Setup return arg. */

  if (string_return == NULL)
    string = NULL;
  else if (*string_return == NULL)
    string = g_string_sized_new (8192);
  else
    string = *string_return;

  /* Read until encountering end of file or error. */

  while (1)
    {
      int count;
      while (1)
        {
          g_debug ("   asking for %i\n", BUFFER_SIZE);
          count = read (socket, buffer, BUFFER_SIZE);
          if (count < 0)
            {
              if (errno == EINTR)
                /* Interrupted, try read again. */
                continue;
              if (timeout > 0)
                {
                  if (errno == EAGAIN)
                    {
                      /* Server still busy, either timeout or try read again. */
                      if ((timeout - (time (NULL) - last_time)) <= 0)
                        {
                          g_warning ("   timeout\n");
                          if (fcntl (socket, F_SETFL, 0L) < 0)
                            g_warning ("%s :failed to set socket flag: %s",
                                       __func__, strerror (errno));
                          g_free (buffer);
                          if (string && *string_return == NULL)
                            g_string_free (string, TRUE);
                          return -4;
                        }
                    }
                  continue;
                }
              if (string && *string_return == NULL)
                g_string_free (string, TRUE);
              if (timeout > 0)
                fcntl (socket, F_SETFL, 0L);
              g_free (buffer);
              return -1;
            }
          if (count == 0)
            {
              /* End of file. */
              if (timeout > 0)
                {
                  if (fcntl (socket, F_SETFL, 0L) < 0)
                    g_warning ("%s :failed to set socket flag: %s", __func__,
                               strerror (errno));
                }
              if (string)
                *string_return = string;
              g_free (buffer);
              return 0;
            }
          break;
        }

      g_debug ("<= %.*s\n", (int) count, buffer);

      if (string)
        g_string_append_len (string, buffer, count);

      if ((timeout > 0) && (time (&last_time) == -1))
        {
          g_warning ("   failed to get current time (1): %s\n",
                     strerror (errno));
          if (fcntl (socket, F_SETFL, 0L) < 0)
            g_warning ("%s :failed to set server socket flag: %s", __func__,
                       strerror (errno));
          g_free (buffer);
          if (string && *string_return == NULL)
            g_string_free (string, TRUE);
          return -1;
        }
    }
}

/**
 * @brief Try read an XML entity tree from the socket.
 *
 * @param[in]   socket         Socket to read from.
 * @param[in]   timeout        Server idle time before giving up, in seconds.  0
 * to wait forever.
 * @param[out]  entity         Pointer to an entity tree.
 * @param[out]  string_return  An optional return location for the text read
 *                             from the session.  If NULL then it simply
 *                             remains NULL.  If a pointer to NULL then it
 * points to a freshly allocated GString on successful return. Otherwise it
 * points to an existing GString onto which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout,
 * -5 null buffer.
 */
static int
try_read_entity_and_string_s (int socket, int timeout, entity_t *entity,
                              GString **string_return)
{
  GMarkupParser xml_parser;
  GError *error = NULL;
  GMarkupParseContext *xml_context;
  GString *string;
  time_t last_time;
  /* Buffer for reading from the socket. */
  char *buffer;

  /* Record the start time. */

  if (time (&last_time) == -1)
    {
      g_warning ("   failed to get current time: %s\n", strerror (errno));
      return -1;
    }

  if (timeout > 0)
    {
      /* Turn off blocking. */

      if (fcntl (socket, F_SETFL, O_NONBLOCK) == -1)
        return -1;
    }

  buffer = g_malloc0 (BUFFER_SIZE);
  if (!buffer)
    return -5;

  /* Setup return arg. */

  if (string_return == NULL)
    string = NULL;
  else if (*string_return == NULL)
    string = g_string_new ("");
  else
    string = *string_return;

  /* Create the XML parser. */

  if (entity)
    {
      xml_parser.start_element = handle_start_element;
      xml_parser.end_element = handle_end_element;
      xml_parser.text = handle_text;
    }
  else
    {
      xml_parser.start_element = ignore_start_element;
      xml_parser.end_element = ignore_end_element;
      xml_parser.text = ignore_text;
    }
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
      int count;
      while (1)
        {
          g_debug ("   asking for %i\n", BUFFER_SIZE);
          count = read (socket, buffer, BUFFER_SIZE);
          if (count < 0)
            {
              if (errno == EINTR)
                /* Interrupted, try read again. */
                continue;
              if (timeout > 0)
                {
                  if (errno == EAGAIN)
                    {
                      /* Server still busy, either timeout or try read again. */
                      if ((timeout - (time (NULL) - last_time)) <= 0)
                        {
                          g_warning ("   timeout\n");
                          if (fcntl (socket, F_SETFL, 0L) < 0)
                            g_warning ("%s :failed to set socket flag: %s",
                                       __func__, strerror (errno));
                          g_markup_parse_context_free (xml_context);
                          g_free (buffer);
                          if (string && *string_return == NULL)
                            g_string_free (string, TRUE);
                          return -4;
                        }
                    }
                  continue;
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
              g_free (buffer);
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
                {
                  if (fcntl (socket, F_SETFL, 0L) < 0)
                    g_warning ("%s :failed to set socket flag: %s", __func__,
                               strerror (errno));
                }
              g_markup_parse_context_free (xml_context);
              g_free (buffer);
              return -3;
            }
          break;
        }

      g_debug ("<= %.*s\n", (int) count, buffer);

      if (string)
        g_string_append_len (string, buffer, count);

      g_markup_parse_context_parse (xml_context, buffer, count, &error);
      if (error)
        {
          g_error_free (error);
          // FIX there may be multiple entries in list
          if (context_data.first && context_data.first->data)
            {
              free_entity (context_data.first->data);
              g_slist_free_1 (context_data.first);
            }
          if (string && *string_return == NULL)
            g_string_free (string, TRUE);
          if (timeout > 0)
            {
              if (fcntl (socket, F_SETFL, 0L) < 0)
                g_warning ("%s :failed to set socket flag: %s", __func__,
                           strerror (errno));
            }
          g_markup_parse_context_free (xml_context);
          g_free (buffer);
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
              g_free (buffer);
              if (string && *string_return == NULL)
                g_string_free (string, TRUE);
              return -2;
            }
          if (entity)
            *entity = (entity_t) context_data.first->data;
          if (string)
            *string_return = string;
          if (timeout > 0)
            fcntl (socket, F_SETFL, 0L);
          g_slist_free (context_data.first);
          g_markup_parse_context_free (xml_context);
          g_free (buffer);
          return 0;
        }

      if ((timeout > 0) && (time (&last_time) == -1))
        {
          g_warning ("   failed to get current time (1): %s\n",
                     strerror (errno));
          if (fcntl (socket, F_SETFL, 0L) < 0)
            g_warning ("%s :failed to set server socket flag: %s", __func__,
                       strerror (errno));
          g_markup_parse_context_free (xml_context);
          g_free (buffer);
          if (string && *string_return == NULL)
            g_string_free (string, TRUE);
          return -1;
        }
    }
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   session          Pointer to GNUTLS session.
 * @param[out]  entity           Pointer to an entity tree.
 * @param[out]  string_return    An optional return location for the text read
 *                               from the session.  If NULL then it simply
 *                               remains NULL.  If a pointer to NULL then it
 * points to a freshly allocated GString on successful return. Otherwise it
 * points to an existing GString onto which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity_and_string (gnutls_session_t *session, entity_t *entity,
                        GString **string_return)
{
  return try_read_entity_and_string (session, 0, entity, string_return);
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   connection       Connection.
 * @param[out]  entity           Pointer to an entity tree.
 * @param[out]  string_return    An optional return location for the text read
 *                               from the session.  If NULL then it simply
 *                               remains NULL.  If a pointer to NULL then it
 * points to a freshly allocated GString on successful return. Otherwise it
 * points to an existing GString onto which the text is appended.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity_and_string_c (gvm_connection_t *connection, entity_t *entity,
                          GString **string_return)
{
  if (connection->tls)
    return try_read_entity_and_string (&connection->session, 0, entity,
                                       string_return);
  return try_read_entity_and_string_s (connection->socket, 0, entity,
                                       string_return);
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
read_entity_and_text (gnutls_session_t *session, entity_t *entity, char **text)
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
 * @brief Read an XML entity tree from the manager.
 *
 * @param[in]   connection  Connection.
 * @param[out]  entity      Entity tree.
 * @param[out]  text      A pointer to a pointer, at which to store the
 *                        address of a newly allocated string holding the
 *                        text read from the session, if the text is required,
 *                        else NULL.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity_and_text_c (gvm_connection_t *connection, entity_t *entity,
                        char **text)
{
  if (text)
    {
      GString *string = NULL;
      int ret = read_entity_and_string_c (connection, entity, &string);
      if (ret)
        {
          if (string)
            g_string_free (string, TRUE);
          return ret;
        }
      *text = g_string_free (string, FALSE);
      return 0;
    }
  return read_entity_and_string_c (connection, entity, NULL);
}

/**
 * @brief Read text from the server.
 *
 * @param[in]  connection  Connection.
 * @param[out] text        A pointer to a pointer, at which to store the
 *                         address of a newly allocated string holding the
 *                         text read from the session.
 *
 * @return 0 success, -1 read error, -2 argument error.
 */
int
read_text_c (gvm_connection_t *connection, char **text)
{
  GString *string;
  int ret;

  if (text == NULL)
    return -2;

  string = NULL;

  if (connection->tls)
    ret = try_read_string (&connection->session, 0, &string);
  else
    ret = try_read_string_s (connection->socket, 0, &string);

  if (ret)
    {
      if (string)
        g_string_free (string, TRUE);
      return ret;
    }
  *text = g_string_free (string, FALSE);
  return 0;
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
read_string (gnutls_session_t *session, GString **string)
{
  int ret = 0;
  entity_t entity;

  if (!(ret = read_entity_and_string (session, &entity, string)))
    free_entity (entity);

  return ret;
}

/**
 * @brief Read entity and text. Free the entity immediately.
 *
 * @param[in]   connection  Connection.
 * @param[out]  string      Return location for the string.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_string_c (gvm_connection_t *connection, GString **string)
{
  return read_entity_and_string_c (connection, NULL, string);
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   timeout   Server idle time before giving up, in seconds.  0 to
 *                        wait forever.
 * @param[out]  entity    Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout.
 */
int
try_read_entity (gnutls_session_t *session, int timeout, entity_t *entity)
{
  return try_read_entity_and_string (session, timeout, entity, NULL);
}

/**
 * @brief Try read an XML entity tree from the manager.
 *
 * @param[in]   connection  Connection.
 * @param[in]   timeout     Server idle time before giving up, in seconds.  0 to
 *                          wait forever.
 * @param[out]  entity      Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file, -4 timeout.
 */
int
try_read_entity_c (gvm_connection_t *connection, int timeout, entity_t *entity)
{
  if (connection->tls)
    return try_read_entity_and_string (&connection->session, 0, entity, NULL);
  return try_read_entity_and_string_s (connection->socket, timeout, entity,
                                       NULL);
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
read_entity (gnutls_session_t *session, entity_t *entity)
{
  return try_read_entity (session, 0, entity);
}

/**
 * @brief Read an XML entity tree from the socket.
 *
 * @param[in]   socket    Socket to read from.
 * @param[out]  entity    Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity_s (int socket, entity_t *entity)
{
  return try_read_entity_and_string_s (socket, 0, entity, NULL);
}

/**
 * @brief Read an XML entity tree from the manager.
 *
 * @param[in]   connection Connection.
 * @param[out]  entity     Pointer to an entity tree.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 end of file.
 */
int
read_entity_c (gvm_connection_t *connection, entity_t *entity)
{
  return try_read_entity_c (connection, 0, entity);
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
parse_entity (const char *string, entity_t *entity)
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
  gchar *text_escaped;
  text_escaped = g_markup_escape_text ((gchar *) value, -1);
  g_string_append_printf ((GString *) string, " %s=\"%s\"", (char *) name,
                          text_escaped);
  g_free (text_escaped);
}

/**
 * @brief Print an XML entity tree to a GString, appending it if string is not
 * @brief empty.
 *
 * @param[in]      entity  Entity tree to print to string.
 * @param[in,out]  string  String to write to.
 */
void
print_entity_to_string (entity_t entity, GString *string)
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
print_entity (FILE *stream, entity_t entity)
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
  (void) none;
  printf (" %s=\"%s\"", (char *) name, (char *) value);
}

/**
 * @brief Print an XML entity to stdout, recursively printing its children.
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
static gboolean
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
      if (g_hash_table_find (entity1->attributes, compare_find_attribute,
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

/* XML file utilities */

/**
 * @brief Handle the opening tag of an element in an XML search.
 *
 * @param[in]   ctx               The parse context.
 * @param[in]   element_name      The name of the element.
 * @param[in]   attribute_names   NULL-terminated array of attribute names.
 * @param[in]   attribute_values  NULL-terminated array of attribute values.
 * @param[in]   data              The search data struct.
 * @param[out]  error             Pointer to error output location.
 */
static void
xml_search_handle_start_element (GMarkupParseContext *ctx,
                                 const gchar *element_name,
                                 const gchar **attribute_names,
                                 const gchar **attribute_values, gpointer data,
                                 GError **error)
{
  (void) ctx;
  (void) error;

  xml_search_data_t *search_data = ((xml_search_data_t *) data);

  if (strcmp (element_name, search_data->find_element) == 0
      && search_data->found == 0)
    {
      g_debug ("%s: Found element <%s>", __func__, element_name);

      if (search_data->find_attributes
          && g_hash_table_size (search_data->find_attributes))
        {
          int index;
          GHashTable *found_attributes;
          found_attributes =
            g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
          index = 0;
          while (attribute_names[index])
            {
              gchar *searched_value;
              searched_value = g_hash_table_lookup (
                search_data->find_attributes, attribute_names[index]);
              if (searched_value
                  && strcmp (searched_value, attribute_values[index]) == 0)
                {
                  g_debug ("%s: Found attribute %s=\"%s\"", __func__,
                           attribute_names[index], searched_value);
                  g_hash_table_add (found_attributes, searched_value);
                }
              index++;
            }
          g_debug ("%s: Found %d of %d attributes", __func__,
                   g_hash_table_size (found_attributes),
                   g_hash_table_size (search_data->find_attributes));

          if (g_hash_table_size (found_attributes)
              == g_hash_table_size (search_data->find_attributes))
            {
              search_data->found = 1;
            }

          g_hash_table_destroy (found_attributes);
        }
      else
        {
          search_data->found = 1;
        }
    }
}

#define XML_FILE_BUFFER_SIZE 1048576
int
/**
 * @brief Tests if an XML file contains an element with given attributes.
 *
 * @param[in]   file_path         Path of the XML file.
 * @param[in]   find_element      Name of the element to find.
 * @param[in]   find_attributes   GHashTable of attributes to find.
 *
 * @return  1 if element was found, 0 if not.
 */
find_element_in_xml_file (gchar *file_path, gchar *find_element,
                          GHashTable *find_attributes)
{
  gchar buffer[XML_FILE_BUFFER_SIZE];
  FILE *file;
  int read_len;
  GMarkupParser xml_parser;
  GMarkupParseContext *xml_context;
  xml_search_data_t search_data;
  GError *error = NULL;

  search_data.find_element = find_element;
  search_data.find_attributes = find_attributes;
  search_data.found = 0;

  /* Create the XML parser. */
  xml_parser.start_element = xml_search_handle_start_element;
  xml_parser.end_element = NULL;
  xml_parser.text = NULL;
  xml_parser.passthrough = NULL;
  xml_parser.error = NULL;
  xml_context = g_markup_parse_context_new (&xml_parser, 0, &search_data, NULL);

  file = fopen (file_path, "r");
  if (file == NULL)
    {
      g_markup_parse_context_free (xml_context);
      g_warning ("%s: Failed to open '%s':", __func__, strerror (errno));
      return 0;
    }

  while ((read_len = fread (&buffer, sizeof (char), XML_FILE_BUFFER_SIZE, file))
         && g_markup_parse_context_parse (xml_context, buffer, read_len, &error)
         && error == NULL)
    {
    }
  g_markup_parse_context_end_parse (xml_context, &error);

  fclose (file);

  g_markup_parse_context_free (xml_context);
  return search_data.found;
}
#undef XML_FILE_BUFFER_SIZE

/* The new faster parser that uses libxml2. */

/**
 * @brief Read an XML element tree from a string.
 *
 * Caller must not free string until caller is finished using element.
 *
 * @param[in]   string   Input string.
 * @param[out]  element  Location for parsed element tree, or NULL if not
 *                       required.   If given, set to NULL on failure.
 *                       Free with element_free.
 *
 * @return 0 success, -1 read error, -2 parse error, -3 XML ended prematurely,
 *         -4 setup error.
 */
int
parse_element (const gchar *string, element_t *element)
{
  xmlDocPtr doc;

  LIBXML_TEST_VERSION

  if (element)
    *element = NULL;

  if (xmlMemSetup (g_free, g_malloc, g_realloc, g_strdup))
    return -4;

  doc =
    xmlReadMemory (string, strlen (string), "noname.xml", NULL, XML_PARSE_HUGE);
  if (doc == NULL)
    return -2;

  if (element)
    *element = xmlDocGetRootElement (doc);

  return 0;
}

/**
 * @brief Free an entire element tree.
 *
 * Beware that this frees the entire tree that element is part of, including
 * any ancestors.
 *
 * @param[in]  element  Element.
 */
void
element_free (element_t element)
{
  if (element)
    {
      assert (element->doc);
      xmlFreeDoc (element->doc);
    }
}

/**
 * @brief Get the name of an element.
 *
 * @param[in]  element  Element.
 *
 * @return Element name.
 */
const gchar *
element_name (element_t element)
{
  if (element && (element->type == XML_ELEMENT_NODE))
    return (const gchar *) element->name;

  return "";
}

/**
 * @brief Find child in an element.
 *
 * @param[in]  element  Element.
 * @param[in]  name     Name of child.
 *
 * @return Child if found, else NULL.
 */
static element_t
find_child (element_t element, const gchar *name)
{
  for (xmlNode *node = element->children; node; node = node->next)
    if (xmlStrcmp (node->name, (const xmlChar *) name) == 0)
      return node;
  return NULL;
}

/**
 * @brief Get a child of an element.
 *
 * @param[in]  element  Element.
 * @param[in]  name    Name of the child.
 *
 * @return Element if found, else NULL.
 */
element_t
element_child (element_t element, const gchar *name)
{
  const gchar *stripped_name;

  if (!element)
    return NULL;

  stripped_name = strchr (name, ':');
  if (stripped_name)
    {
      element_t child;

      /* There was a namespace in the name.
       *
       * First try without the namespace, because libxml2 doesn't consider the
       * namespace in the name when the namespace is defined. */

      stripped_name++;

      if (*stripped_name == '\0')
        /* Don't search for child with empty stripped name, because we'll
         * find text nodes.  But search with just the namespace for glib
         * compatibility. */
        return find_child (element, name);

      child = find_child (element, stripped_name);
      if (child)
        return child;

      /* Didn't find anything. */
    }

  /* There was no namespace, or we didn't find anything without the namespace.
   *
   * Try with the full name. */

  return find_child (element, name);
}

/**
 * @brief Get text of an element.
 *
 * If element is not NULL then the return is guaranteed to be a string.
 * So if the caller has NULL checked element then there is no need for
 * the caller to NULL check the return.
 *
 * @param[in]  element  Element.
 *
 * @return NULL if element is NULL, else the text.  Caller must g_free.
 */
gchar *
element_text (element_t element)
{
  gchar *string;

  if (!element)
    return NULL;

  string =
    (gchar *) xmlNodeListGetString (element->doc, element->xmlChildrenNode, 1);
  if (string)
    return string;
  string = xmlMalloc (1);
  string[0] = '\0';
  return string;
}

/**
 * @brief Get an attribute of an element.
 *
 * @param[in]  element  Element.
 * @param[in]  name     Name of the attribute.
 *
 * @return Attribute value if found, else NULL.  Caller must g_free.
 */
gchar *
element_attribute (element_t element, const gchar *name)
{
  const gchar *stripped_name;

  if (!element)
    return NULL;

  stripped_name = strchr (name, ':');
  if (stripped_name)
    {
      gchar *attribute;

      /* There was a namespace in the name.
       *
       * First try without the namespace, because libxml2 doesn't consider the
       * namespace in the name when the namespace is defined. */

      stripped_name++;

      if (*stripped_name == '\0')
        /* Don't search for child with empty stripped name, because we'll
         * find text nodes.  But search with just the namespace for glib
         * compatibility. */
        return (gchar *) xmlGetProp (element, (const xmlChar *) name);

      attribute =
        (gchar *) xmlGetProp (element, (const xmlChar *) stripped_name);
      if (attribute)
        return attribute;

      /* Didn't find anything. */
    }

  /* There was no namespace, or we didn't find anything without the namespace.
   *
   * Try with the full name. */

  return (gchar *) xmlGetProp (element, (const xmlChar *) name);
}

/**
 * @brief Get the first child of an element.
 *
 * @param[in]  element  Element.
 *
 * @return Child if there is one, else NULL.
 */
element_t
element_first_child (element_t element)
{
  if (element)
    {
      element = element->children;
      while (element && (element->type != XML_ELEMENT_NODE))
        element = element->next;
      return element;
    }
  return NULL;
}

/**
 * @brief Get the next sibling of an element
 *
 * @param[in]  element  Element.
 *
 * @return Next sibling element if there is one, else NULL.
 */
element_t
element_next (element_t element)
{
  if (element)
    {
      element = element->next;
      while (element && (element->type != XML_ELEMENT_NODE))
        element = element->next;
      return element;
    }
  return NULL;
}

/**
 * @brief Output the XML element as a string.
 *
 * The generated XML string will include namespace definitions from ancestor
 *  elements.
 *
 * @param[in]  element  The element to output as a string.
 *
 * @return The newly allocated XML string.
 */
gchar *
element_to_string (element_t element)
{
  xmlBufferPtr buffer;
  char *xml_string;

  // Copy element to ensure XML namespaces are included
  element_t element_copy;
  element_copy = xmlCopyNode (element, 1);

  buffer = xmlBufferCreate ();
  xmlNodeDump (buffer, element_copy->doc, element_copy, 0, 0);
  xmlFreeNode (element_copy);

  xml_string = g_strdup ((char *) xmlBufferContent (buffer));

  xmlBufferFree (buffer);
  return xml_string;
}

/**
 * @brief Print an XML element tree to a GString, appending it if string is not
 * @brief empty.
 *
 * @param[in]      element  Element tree to print to string.
 * @param[in,out]  string  String to write to.
 */
void
print_element_to_string (element_t element, GString *string)
{
  gchar *text_escaped, *text;
  element_t ch;
  xmlAttr *attribute;

  text_escaped = NULL;

  g_string_append_printf (string, "<%s", element_name (element));

  attribute = element->properties;
  while (attribute)
    {
      xmlChar *value;

      value = xmlNodeListGetString (element->doc, attribute->children, 1);

      text_escaped = g_markup_escape_text ((gchar *) value, -1);
      g_string_append_printf (string, " %s=\"%s\"", attribute->name,
                              text_escaped);
      g_free (text_escaped);

      xmlFree (value);

      attribute = attribute->next;
    }

  g_string_append_printf (string, ">");

  text = element_text (element);
  text_escaped = g_markup_escape_text (text, -1);
  g_free (text);
  g_string_append_printf (string, "%s", text_escaped);
  g_free (text_escaped);

  ch = element_first_child (element);
  while (ch)
    {
      print_element_to_string (ch, string);
      ch = element_next (ch);
    }

  g_string_append_printf (string, "</%s>", element_name (element));
}

/* XML file iterator */

/**
 * @brief Opaque data structure for XML file iterator
 */
struct xml_file_iterator_struct
{
  int initialized;              //< Whether the iterator is initialized.
  int output_depth;             //< Tree depth at which to output subelements
  GQueue *element_queue;        //< Queue of parsed XML subelements
  xmlSAXHandler sax_handler;    //< SAX handler structure
  xmlParserCtxtPtr parser_ctxt; //< libXML parser context for building DOM
  gchar *file_path;             //< Path to the XML file being processed
  FILE *file;                   //< Stream pointer for the XML file
};

/**
 * @brief XML file iterator parser callback for element start.
 *
 * This is just a wrapper for the libXML xmlSAX2StartElementNs getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] localname     the local name of the element
 * @param[in] prefix        the element namespace prefix if available
 * @param[in] URI           the element namespace name if available
 * @param[in] nb_namespaces number of namespace definitions on that node
 * @param[in] namespaces    pointer to the array of prefix/URI pairs namespace
 *                          definitions
 * @param[in] nb_attributes the number of attributes on that node
 * @param[in] nb_defaulted  the number of defaulted attributes
 * @param[in] attributes    pointer to the array of
 *                          (localname/prefix/URI/value/end) attribute values
 */
static void
xml_file_iterator_start_element_ns (void *ctx, const xmlChar *localname,
                                    const xmlChar *prefix, const xmlChar *URI,
                                    int nb_namespaces,
                                    const xmlChar **namespaces,
                                    int nb_attributes, int nb_defaulted,
                                    const xmlChar **attributes)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2StartElementNs (iterator->parser_ctxt, localname, prefix, URI,
                         nb_namespaces, namespaces, nb_attributes, nb_defaulted,
                         attributes);
}

/**
 * @brief XML file iterator parser callback for element end.
 *
 * This uses xmlSAX2EndElementNs to finish parsing the element to the document
 *  in the libXML parser context of the iterator.
 * If the element is at the output tree depth defined in the iterator
 *  then it is removed from the document and added to the element queue of
 *  the iterator.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] localname     the local name of the element
 * @param[in] prefix        the element namespace prefix if available
 * @param[in] URI           the element namespace name if available
 */
static void
xml_file_iterator_end_element_ns (void *ctx, const xmlChar *localname,
                                  const xmlChar *prefix, const xmlChar *URI)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2EndElementNs (iterator->parser_ctxt, localname, prefix, URI);

  if (iterator->parser_ctxt->nodeNr == iterator->output_depth)
    {
      xmlNodePtr parent, child;
      parent = iterator->parser_ctxt->node;

      child = parent->children;
      while (child)
        {
          if (child->type == XML_ELEMENT_NODE)
            {
              xmlDocPtr new_doc = xmlNewDoc ((const xmlChar *) "1.0");
              element_t child_copy;
              child_copy = xmlCopyNode (child, 1);
              xmlDocSetRootElement (new_doc, child_copy);

              if (child_copy)
                {
                  g_queue_push_tail (iterator->element_queue, child_copy);
                }
            }

          xmlUnlinkNode (child);
          xmlFreeNode (child);

          child = parent->children;
        }
    }
}

/**
 * @brief XML file iterator parser callback for internal subset declaration.
 *
 * This is just a wrapper for the libXML xmlSAX2InternalSubset getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          the root element name
 * @param[in] ExternalID    the external ID
 * @param[in] SystemID      the SYSTEM ID (e.g. filename or URL)
 */
static void
xml_file_iterator_internal_subset (void *ctx, const xmlChar *name,
                                   const xmlChar *ExternalID,
                                   const xmlChar *SystemID)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2InternalSubset (iterator->parser_ctxt, name, ExternalID, SystemID);
}

/**
 * @brief XML file iterator parser callback for external subset declaration.
 *
 * This is just a wrapper for the libXML xmlSAX2ExternalSubset getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          the root element name
 * @param[in] ExternalID    the external ID
 * @param[in] SystemID      the SYSTEM ID (e.g. filename or URL)
 */
static void
xml_file_iterator_external_subset (void *ctx, const xmlChar *name,
                                   const xmlChar *ExternalID,
                                   const xmlChar *SystemID)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2ExternalSubset (iterator->parser_ctxt, name, ExternalID, SystemID);
}

/**
 * @brief XML file iterator parser callback for checking if doc is standalone.
 *
 * This is just a wrapper for the libXML xmlSAX2IsStandalone getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 *
 * @return 1 if true
 */
static int
xml_file_iterator_is_standalone (void *ctx)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  return xmlSAX2IsStandalone (iterator->parser_ctxt);
}

/**
 * @brief XML file iterator parser callback for checking if doc has an
 *        internal subset.
 *
 * This is just a wrapper for the libXML xmlSAX2HasInternalSubset getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 *
 * @return 1 if true
 */
static int
xml_file_iterator_has_internal_subset (void *ctx)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  return xmlSAX2HasInternalSubset (iterator->parser_ctxt);
}

/**
 * @brief XML file iterator parser callback for checking if doc has an
 *        external subset.
 *
 * This is just a wrapper for the libXML xmlSAX2HasExternalSubset getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 *
 * @return 1 if true
 */
static int
xml_file_iterator_has_external_subset (void *ctx)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  return xmlSAX2HasExternalSubset (iterator->parser_ctxt);
}

/**
 * @brief XML file iterator parser callback for resolving an entity.
 *
 * This is just a wrapper for the libXML xmlSAX2ResolveEntity getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] publicId      The public ID of the entity
 * @param[in] systemId      The systemID of the entity
 *
 * @return the xmlParserInputPtr if inlined or NULL for DOM behaviour
 */
static xmlParserInputPtr
xml_file_iterator_resolve_entity (void *ctx, const xmlChar *publicId,
                                  const xmlChar *systemId)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  return xmlSAX2ResolveEntity (iterator->parser_ctxt, publicId, systemId);
}

/**
 * @brief XML file iterator parser callback for getting an entity by name.
 *
 * This is just a wrapper for the libXML xmlSAX2GetEntity getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          The entity name
 *
 * @return the xmlEntityPtr if found
 */
static xmlEntityPtr
xml_file_iterator_get_entity (void *ctx, const xmlChar *name)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  return xmlSAX2GetEntity (iterator->parser_ctxt, name);
}

/**
 * @brief XML file iterator parser callback for getting a parameter entity
 *        by name.
 *
 * This is just a wrapper for the libXML xmlSAX2GetParameterEntity getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          The entity name
 *
 * @return the xmlEntityPtr if found
 */
static xmlEntityPtr
xml_file_iterator_get_parameter_entity (void *ctx, const xmlChar *name)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  return xmlSAX2GetParameterEntity (iterator->parser_ctxt, name);
}

/**
 * @brief XML file iterator parser callback for when an entity definition has
 *        been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2EntityDecl getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          the entity name
 * @param[in] type          the entity type
 * @param[in] publicId      The public ID of the entity
 * @param[in] systemId      The system ID of the entity
 * @param[in] content       the entity value (without processing)
 */
static void
xml_file_iterator_entity_decl (void *ctx, const xmlChar *name, int type,
                               const xmlChar *publicId, const xmlChar *systemId,
                               xmlChar *content)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2EntityDecl (iterator->parser_ctxt, name, type, publicId, systemId,
                     content);
}

/**
 * @brief XML file iterator parser callback for when an attribute definition
 *        has been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2AttributeDecl getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          the name of the element
 * @param[in] fullname      the attribute name
 * @param[in] type          the attribute type
 * @param[in] def           the type of default value
 * @param[in] defaultValue  the attribute default value
 * @param[in] tree          the tree of enumerated value set
 */
static void
xml_file_iterator_attribute_decl (void *ctx, const xmlChar *elem,
                                  const xmlChar *fullname, int type, int def,
                                  const xmlChar *defaultValue,
                                  xmlEnumerationPtr tree)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2AttributeDecl (iterator->parser_ctxt, elem, fullname, type, def,
                        defaultValue, tree);
}

/**
 * @brief XML file iterator parser callback for when an element definition
 *        has been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2ElementDecl getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          the element name
 * @param[in] type          the element type
 * @param[in] def           the type of default value
 * @param[in] defaultValue  the attribute default value
 * @param[in] content       the element value tree
 */
static void
xml_file_iterator_element_decl (void *ctx, const xmlChar *name, int type,
                                xmlElementContentPtr content)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2ElementDecl (iterator->parser_ctxt, name, type, content);
}

/**
 * @brief XML file iterator parser callback for when a notation definition
 *        has been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2NotationDecl getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          The name of the notation
 * @param[in] publicId      The public ID of the entity
 * @param[in] systemId      The system ID of the entity
 */
static void
xml_file_iterator_notation_decl (void *ctx, const xmlChar *name,
                                 const xmlChar *publicId,
                                 const xmlChar *systemId)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2NotationDecl (iterator->parser_ctxt, name, publicId, systemId);
}

/**
 * @brief XML file iterator parser callback for when an unparsed entity
 *        declaration has been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2UnparsedEntityDecl getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] name          The name of the notation
 * @param[in] publicId      The public ID of the entity
 * @param[in] systemId      The system ID of the entity
 * @param[in] notationName  The name of the notation
 */
static void
xml_file_iterator_unparsed_entity_decl (void *ctx, const xmlChar *name,
                                        const xmlChar *publicId,
                                        const xmlChar *systemId,
                                        const xmlChar *notationName)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2UnparsedEntityDecl (iterator->parser_ctxt, name, publicId, systemId,
                             notationName);
}

/**
 * @brief XML file iterator parser callback for setting the document locator.
 *
 * This is just a wrapper for the libXML xmlSAX2SetDocumentLocator getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] loc           A SAX Locator
 */
static void
xml_file_iterator_set_document_locator (void *ctx, xmlSAXLocatorPtr loc)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2SetDocumentLocator (iterator->parser_ctxt, loc);
}

/**
 * @brief XML file iterator parser callback at the document start.
 *
 * This is just a wrapper for the libXML xmlSAX2StartDocument getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 */
static void
xml_file_iterator_start_document (void *ctx)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2StartDocument (iterator->parser_ctxt);
}

/**
 * @brief XML file iterator parser callback at the document end.
 *
 * This is just a wrapper for the libXML xmlSAX2EndDocument getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 */
static void
xml_file_iterator_end_document (void *ctx)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2EndDocument (iterator->parser_ctxt);
}

/**
 * @brief XML file iterator parser callback when receiving some chars from
 *        the parser.
 *
 * This is just a wrapper for the libXML xmlSAX2Characters getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] ch            a xmlChar string
 * @param[in] len           the number of xmlChar
 */
static void
xml_file_iterator_characters (void *ctx, const xmlChar *ch, int len)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2Characters (iterator->parser_ctxt, ch, len);
}

/**
 * @brief XML file iterator parser callback when a pcdata block has
 *        been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2CDataBlock getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] ch            The pcdata content
 * @param[in] len           the block length
 */
static void
xml_file_iterator_cdata_block (void *ctx, const xmlChar *ch, int len)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2CDataBlock (iterator->parser_ctxt, ch, len);
}

/**
 * @brief XML file iterator parser callback when a processing instruction has
 *        been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2ProcessingInstruction getting
 * the libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] target        The target name
 * @param[in] data          the PI data
 */
static void
xml_file_iterator_processing_instruction (void *ctx, const xmlChar *target,
                                          const xmlChar *data)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2ProcessingInstruction (iterator->parser_ctxt, target, data);
}

/**
 * @brief XML file iterator parser callback when a comment has been parsed.
 *
 * This is just a wrapper for the libXML xmlSAX2Comment getting the
 * libXML parser context from the iterator struct passed as user data.
 *
 * @param[in] ctx           parser context data / iterator data structure
 * @param[in] value         the comment content
 */
static void
xml_file_iterator_comment (void *ctx, const xmlChar *value)
{
  xml_file_iterator_t iterator = (xml_file_iterator_t) ctx;
  xmlSAX2Comment (iterator->parser_ctxt, value);
}

/**
 * @brief Initializes a xmlSAXHandler data structure for SAX version 2 parsing,
 *        assigning all the XML file iterator callback functions.
 *
 * @param[in] hdlr  The xmlSAXHandler to initialize
 */
static void
xml_file_iterator_init_sax_handler (xmlSAXHandler *hdlr)
{
  hdlr->startElementNs = xml_file_iterator_start_element_ns;
  hdlr->endElementNs = xml_file_iterator_end_element_ns;
  hdlr->error = NULL;
  hdlr->initialized = XML_SAX2_MAGIC;
  hdlr->startElement = NULL;
  hdlr->endElement = NULL;
  hdlr->internalSubset = xml_file_iterator_internal_subset;
  hdlr->externalSubset = xml_file_iterator_external_subset;
  hdlr->isStandalone = xml_file_iterator_is_standalone;
  hdlr->hasInternalSubset = xml_file_iterator_has_internal_subset;
  hdlr->hasExternalSubset = xml_file_iterator_has_external_subset;
  hdlr->resolveEntity = xml_file_iterator_resolve_entity;
  hdlr->getEntity = xml_file_iterator_get_entity;
  hdlr->getParameterEntity = xml_file_iterator_get_parameter_entity;
  hdlr->entityDecl = xml_file_iterator_entity_decl;
  hdlr->attributeDecl = xml_file_iterator_attribute_decl;
  hdlr->elementDecl = xml_file_iterator_element_decl;
  hdlr->notationDecl = xml_file_iterator_notation_decl;
  hdlr->unparsedEntityDecl = xml_file_iterator_unparsed_entity_decl;
  hdlr->setDocumentLocator = xml_file_iterator_set_document_locator;
  hdlr->startDocument = xml_file_iterator_start_document;
  hdlr->endDocument = xml_file_iterator_end_document;
  hdlr->reference = NULL;
  hdlr->characters = xml_file_iterator_characters;
  hdlr->cdataBlock = xml_file_iterator_cdata_block;
  hdlr->ignorableWhitespace = xml_file_iterator_characters;
  hdlr->processingInstruction = xml_file_iterator_processing_instruction;
  hdlr->comment = xml_file_iterator_comment;
  hdlr->warning = xmlParserWarning;
  hdlr->error = xmlParserError;
  hdlr->fatalError = xmlParserError;
}

/**
 * @brief Allocates a new, uninitialized XML file iterator.
 *
 * Free with xml_file_iterator_free.
 *
 * @return Opaque pointer to the XML file iterator data structure.
 */
xml_file_iterator_t
xml_file_iterator_new (void)
{
  return g_malloc0 (sizeof (struct xml_file_iterator_struct));
}

/**
 * @brief Initializes an XML file iterator to read from a given path.
 *
 * @param[in]  iterator         Pointer to the iterator to initialize.
 * @param[in]  file_path        Path to the file to read from.
 * @param[in]  output_depth     XML tree depth at which to return elements.
 *
 * @return -1 error, 0 success, 1 already initialized,
 *         2 error opening file (errno is set to reason)
 */
int
xml_file_iterator_init_from_file_path (xml_file_iterator_t iterator,
                                       const char *file_path, int output_depth)
{
  if (iterator == NULL)
    return -1;

  if (iterator->initialized)
    return 1;

  memset (iterator, 0, sizeof (struct xml_file_iterator_struct));

  LIBXML_TEST_VERSION

  if (output_depth < 0)
    output_depth = 0;
  iterator->output_depth = output_depth;

  iterator->file = fopen (file_path, "rb");
  if (iterator->file == NULL)
    return 2;

  iterator->element_queue = g_queue_new ();

  iterator->file_path = g_strdup (file_path);

  xml_file_iterator_init_sax_handler (&(iterator->sax_handler));
  iterator->parser_ctxt = xmlCreatePushParserCtxt (
    &(iterator->sax_handler), iterator, NULL, 0, iterator->file_path);

  iterator->initialized = 1;

  return 0;
}

/**
 * @brief Frees an XML file iterator and all of its internal data structures
 *
 * @param[in]  iterator  The XML file iterator to free.
 */
void
xml_file_iterator_free (xml_file_iterator_t iterator)
{
  if (iterator == NULL)
    return;

  if (iterator->file)
    {
      fclose (iterator->file);
    }

  g_free (iterator->file_path);

  if (iterator->element_queue)
    {
      g_queue_free_full (iterator->element_queue,
                         (GDestroyNotify) (element_free));
    }

  if (iterator->parser_ctxt)
    {
      xmlFreeParserCtxt (iterator->parser_ctxt);
    }

  g_free (iterator);
}

/**
 * @brief Rewinds an XML file iterator by rewinding the file and creating a
 *        new XML parser context.
 *
 * @param[in]  iterator  The XML file iterator to rewind.
 */
void
xml_file_iterator_rewind (xml_file_iterator_t iterator)
{
  if (iterator == NULL)
    return;

  if (iterator->file)
    {
      rewind (iterator->file);
    }

  if (iterator->element_queue)
    {
      g_queue_clear_full (iterator->element_queue,
                          (GDestroyNotify) (element_free));
    }

  if (iterator->parser_ctxt)
    {
      xmlFreeParserCtxt (iterator->parser_ctxt);
      iterator->parser_ctxt = xmlCreatePushParserCtxt (
        &(iterator->sax_handler), iterator, NULL, 0, iterator->file_path);
    }
}

/**
 * @brief File read buffer size for an XML file iterator.
 */
#define XML_FILE_ITERATOR_BUFFER_SIZE 8192

/**
 * @brief Get the next subelement from a XML file iterator
 *
 * @param[in]  iterator   The XML file iterator to get the element from.
 * @param[out] error      Error message output, set to NULL on success / EOF
 *
 * @return The next subelement (free with element_free) or NULL if finished or
 *         on error.
 */
element_t
xml_file_iterator_next (xml_file_iterator_t iterator, gchar **error)
{
  gboolean continue_read = TRUE;

  if (error)
    *error = NULL;

  if (iterator->initialized == 0)
    {
      if (error)
        *error = g_strdup ("iterator not initialized");
      return NULL;
    }

  while (continue_read && g_queue_is_empty (iterator->element_queue))
    {
      int chars_read;
      char buffer[XML_FILE_ITERATOR_BUFFER_SIZE];

      chars_read =
        fread (buffer, 1, XML_FILE_ITERATOR_BUFFER_SIZE, iterator->file);
      if (chars_read == 0)
        {
          if (feof (iterator->file))
            {
              continue_read = FALSE;
            }
          else if (ferror (iterator->file))
            {
              if (error)
                *error = g_strdup ("error reading file");
              return NULL;
            }
        }
      else
        {
          int ret;
          ret = xmlParseChunk (iterator->parser_ctxt, buffer, chars_read,
                               continue_read == 0);
          if (ret)
            {
              if (error)
                {
                  xmlErrorPtr xml_error;
                  xml_error = xmlCtxtGetLastError (iterator->parser_ctxt);
                  *error = g_strdup_printf ("error parsing XML"
                                            " (line %d column %d): %s",
                                            xml_error->line, xml_error->int2,
                                            xml_error->message);
                }

              return NULL;
            }
        }
    }

  if (!g_queue_is_empty (iterator->element_queue))
    {
      return g_queue_pop_head (iterator->element_queue);
    }

  return NULL;
}
