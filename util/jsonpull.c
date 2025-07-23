/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "jsonpull.h"

#include <assert.h>

#define GVM_JSON_CHAR_EOF -1       ///< End of file
#define GVM_JSON_CHAR_ERROR -2     ///< Error reading file
#define GVM_JSON_CHAR_UNDEFINED -3 ///< Undefined state

/**
 * @brief Creates a new JSON path element.
 *
 * @param[in]  parent_type  Type of the parent (array, object, none/root)
 * @param[in]  depth        The depth in the document tree
 *
 * @return The newly allocated path element
 */
gvm_json_path_elem_t *
gvm_json_pull_path_elem_new (gvm_json_pull_container_type_t parent_type,
                             int depth)
{
  gvm_json_path_elem_t *new_elem = g_malloc0 (sizeof (gvm_json_path_elem_t));
  new_elem->parent_type = parent_type;
  new_elem->depth = depth;
  return new_elem;
}

/**
 * @brief Frees a JSON path element.
 *
 * @param[in]  elem  The element to free
 */
void
gvm_json_pull_path_elem_free (gvm_json_path_elem_t *elem)
{
  g_free (elem->key);
  g_free (elem);
}

/**
 * @brief Initializes a JSON pull event data structure.
 *
 * @param[in]  event  The event structure to initialize
 */
void
gvm_json_pull_event_init (gvm_json_pull_event_t *event)
{
  memset (event, 0, sizeof (gvm_json_pull_event_t));
}

/**
 * @brief Frees all data of JSON pull event data structure.
 *
 * @param[in]  event  The event structure to clean up
 */
void
gvm_json_pull_event_cleanup (gvm_json_pull_event_t *event)
{
  cJSON_Delete (event->value);
  if (event->error_message)
    g_free (event->error_message);
  memset (event, 0, sizeof (gvm_json_pull_event_t));
}

/**
 * @brief Initializes a JSON pull parser.
 *
 * @param[in]  parser         The parser data structure to initialize
 * @param[in]  input_stream   The JSON input stream
 * @param[in]  parse_buffer_limit   Maximum buffer size for parsing values
 * @param[in]  read_buffer_size     Buffer size for reading from the stream
 */
void
gvm_json_pull_parser_init_full (gvm_json_pull_parser_t *parser,
                                FILE *input_stream, size_t parse_buffer_limit,
                                size_t read_buffer_size)
{
  assert (parser);
  assert (input_stream);
  memset (parser, 0, sizeof (gvm_json_pull_parser_t));

  if (parse_buffer_limit <= 0)
    parse_buffer_limit = GVM_JSON_PULL_PARSE_BUFFER_LIMIT;

  if (read_buffer_size <= 0)
    read_buffer_size = GVM_JSON_PULL_READ_BUFFER_SIZE;

  parser->input_stream = input_stream;
  parser->path = g_queue_new ();
  parser->expect = GVM_JSON_PULL_EXPECT_VALUE;
  parser->parse_buffer_limit = parse_buffer_limit;
  parser->parse_buffer = g_string_new ("");
  parser->read_buffer_size = read_buffer_size;
  parser->read_buffer = g_malloc0 (read_buffer_size);
  parser->last_read_char = GVM_JSON_CHAR_UNDEFINED;
}

/**
 * @brief Initializes a JSON pull parser with default buffer sizes.
 *
 * @param[in]  parser         The parser data structure to initialize
 * @param[in]  input_stream   The JSON input stream
 */
void
gvm_json_pull_parser_init (gvm_json_pull_parser_t *parser, FILE *input_stream)
{
  gvm_json_pull_parser_init_full (parser, input_stream, 0, 0);
}

/**
 * @brief Frees the data of a JSON pull parser.
 *
 * @param[in]  parser   The parser data structure to free the data of
 */
void
gvm_json_pull_parser_cleanup (gvm_json_pull_parser_t *parser)
{
  assert (parser);
  g_queue_free_full (parser->path,
                     (GDestroyNotify) gvm_json_pull_path_elem_free);
  g_string_free (parser->parse_buffer, TRUE);
  g_free (parser->read_buffer);
  memset (parser, 0, sizeof (gvm_json_pull_parser_t));
}

/**
 * @brief Generates message for an error that occurred reading the JSON stream.
 *
 * @return The newly allocated error message
 */
static gchar *
gvm_json_read_stream_error_str ()
{
  return g_strdup_printf ("error reading JSON stream: %s", strerror (errno));
}

/**
 * @brief Checks if the parse buffer limit of a JSON pull parser is reached.
 *
 * @param[in]  value_type   The value type to include in the error message
 * @param[in]  parser       The parser to check the parse buffer of
 * @param[in]  event        Event data for error status and message if needed
 *
 * @return 0 if buffer size is okay, 1 if limit was reached
 */
static int
gvm_json_pull_check_parse_buffer_size (const char *value_type,
                                       gvm_json_pull_parser_t *parser,
                                       gvm_json_pull_event_t *event)
{
  if (parser->parse_buffer->len >= parser->parse_buffer_limit)
    {
      event->error_message =
        g_strdup_printf ("%s exceeds size limit of %zu bytes", value_type,
                         parser->parse_buffer_limit);
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      return 1;
    }
  return 0;
}

/**
 * @brief Reads the next character in a pull parser input stream.
 *
 * @param[in]  parser  The parser to read the next character from
 *
 * @return The character code, GVM_JSON_CHAR_ERROR or GVM_JSON_CHAR_EOF.
 */
static int
gvm_json_pull_parser_next_char (gvm_json_pull_parser_t *parser)
{
  parser->read_pos++;
  if (parser->read_pos < parser->last_read_size)
    {
      parser->last_read_char =
        (unsigned char) parser->read_buffer[parser->read_pos];
      return parser->last_read_char;
    }
  else
    {
      parser->read_pos = 0;
      parser->last_read_size = fread (
        parser->read_buffer, 1, parser->read_buffer_size, parser->input_stream);
      if (ferror (parser->input_stream))
        parser->last_read_char = GVM_JSON_CHAR_ERROR;
      else if (parser->last_read_size <= 0)
        parser->last_read_char = GVM_JSON_CHAR_EOF;
      else
        parser->last_read_char =
          (unsigned char) parser->read_buffer[parser->read_pos];
      return parser->last_read_char;
    }
}

/**
 * @brief  Tries to parse the buffer content of a JSON pull parser.
 *
 * @param[in]  parser         The parser to use the parse buffer of
 * @param[in]  event          Event set error of if necessary
 * @param[in]  value_name     Name of the value for error message if needed
 * @param[in]  validate_func  Function for validating the parsed value
 * @param[out] cjson_value    Return of the parsed cJSON object on success
 *
 * @return 0 success, 1 error
 */
static int
gvm_json_pull_parse_buffered (gvm_json_pull_parser_t *parser,
                              gvm_json_pull_event_t *event,
                              const char *value_name,
                              cJSON_bool (*validate_func) (const cJSON *const),
                              cJSON **cjson_value)
{
  cJSON *parsed_value = cJSON_Parse (parser->parse_buffer->str);
  *cjson_value = NULL;
  if (validate_func (parsed_value) == 0)
    {
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      event->error_message = g_strdup_printf ("error parsing %s", value_name);
      cJSON_free (parsed_value);
      return 1;
    }
  *cjson_value = parsed_value;
  return 0;
}

/**
 * @brief Handles error or EOF after reading a character in JSON pull parser.
 *
 * @param[in]  parser     Parser to get the last read character from
 * @param[in]  event      Event data to set EOF or error status in
 * @param[in]  allow_eof  Whether to allow EOF, generate error on EOF if FALSE
 */
static void
gvm_json_pull_handle_read_end (gvm_json_pull_parser_t *parser,
                               gvm_json_pull_event_t *event, gboolean allow_eof)
{
  if (parser->last_read_char == GVM_JSON_CHAR_ERROR)
    {
      event->error_message = gvm_json_read_stream_error_str ();
      event->type = GVM_JSON_PULL_EVENT_ERROR;
    }
  else if (allow_eof)
    event->type = GVM_JSON_PULL_EVENT_EOF;
  else
    {
      event->error_message = g_strdup ("unexpected EOF");
      event->type = GVM_JSON_PULL_EVENT_ERROR;
    }
}

/**
 * @brief Skips whitespaces in the input stream of a JSON pull parser
 *
 * The parser will be at the first non-whitespace character on success.
 *
 * @param[in]  parser     Parser to skip the whitespaces in
 * @param[in]  event      Event data to set EOF or error status in
 * @param[in]  allow_eof  Whether to allow EOF, generate error on EOF if FALSE
 *
 * @return 1 if EOF was reached or an error occurred, 0 otherwise
 */
static int
gvm_json_pull_skip_space (gvm_json_pull_parser_t *parser,
                          gvm_json_pull_event_t *event, gboolean allow_eof)
{
  while (g_ascii_isspace (parser->last_read_char))
    gvm_json_pull_parser_next_char (parser);
  if (parser->last_read_char < 0)
    {
      gvm_json_pull_handle_read_end (parser, event, allow_eof);
      return 1;
    }
  return 0;
}

/**
 * @brief Parses a string in a JSON pull parser.
 *
 * The parser is expected to be at the opening quote mark and will be at the
 * character after the closing quote mark on success.
 *
 * @param[in]  parser       Parser to handle the string value in
 * @param[in]  event        Event data to set EOF or error status in
 * @param[out] cjson_value  The cJSON value for the string on success
 *
 * @return 1 if an error occurred (including EOF), 0 otherwise
 */
static int
gvm_json_pull_parse_string (gvm_json_pull_parser_t *parser,
                            gvm_json_pull_event_t *event, cJSON **cjson_value)
{
  gboolean escape_next_char = FALSE;
  g_string_truncate (parser->parse_buffer, 0);
  g_string_append_c (parser->parse_buffer, '"');
  while (gvm_json_pull_parser_next_char (parser) >= 0)
    {
      if (gvm_json_pull_check_parse_buffer_size ("string", parser, event))
        return 1;
      g_string_append_c (parser->parse_buffer, parser->last_read_char);
      if (escape_next_char)
        escape_next_char = FALSE;
      else if (parser->last_read_char == '\\')
        escape_next_char = TRUE;
      else if (parser->last_read_char == '"')
        break;
    }

  if (parser->last_read_char < 0)
    {
      gvm_json_pull_handle_read_end (parser, event, FALSE);
      return 1;
    }

  gvm_json_pull_parser_next_char (parser);

  return gvm_json_pull_parse_buffered (parser, event, "string", cJSON_IsString,
                                       cjson_value);
}

/**
 * @brief Parses a number in a JSON pull parser.
 *
 * The parser is expected to be at the first character of the number and will
 * be at the first non-number character on success.
 *
 * @param[in]  parser       Parser to handle the number value in
 * @param[in]  event        Event data to set EOF or error status in
 * @param[out] cjson_value  The cJSON value for the number on success.
 *
 * @return 1 if an error occurred, 0 otherwise
 */
static int
gvm_json_pull_parse_number (gvm_json_pull_parser_t *parser,
                            gvm_json_pull_event_t *event, cJSON **cjson_value)
{
  g_string_truncate (parser->parse_buffer, 0);
  g_string_append_c (parser->parse_buffer, parser->last_read_char);
  while (gvm_json_pull_parser_next_char (parser) >= 0)
    {
      if (gvm_json_pull_check_parse_buffer_size ("number", parser, event))
        return 1;
      if (g_ascii_isdigit (parser->last_read_char)
          || parser->last_read_char == '.' || parser->last_read_char == 'e'
          || parser->last_read_char == '-' || parser->last_read_char == '+')
        g_string_append_c (parser->parse_buffer, parser->last_read_char);
      else
        break;
    }

  if (parser->last_read_char == GVM_JSON_CHAR_ERROR)
    {
      event->error_message = gvm_json_read_stream_error_str ();
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      return 1;
    }

  return gvm_json_pull_parse_buffered (parser, event, "number", cJSON_IsNumber,
                                       cjson_value);
}

/**
 * @brief Parses a keyword value in a JSON pull parser.
 *
 * The parser is expected to be at the first character of the keyword and will
 * be at the first character after the keyword on success.
 *
 * @param[in]  parser   Parser to handle the keyword value in
 * @param[in]  event    Event data to set EOF or error status in
 * @param[in]  keyword  The expected keyword, e.g. "null", "true", "false".
 *
 * @return 1 if an error occurred, 0 otherwise
 */
static int
gvm_json_pull_parse_keyword (gvm_json_pull_parser_t *parser,
                             gvm_json_pull_event_t *event, const char *keyword)
{
  for (size_t i = 0; i < strlen (keyword); i++)
    {
      if (parser->last_read_char < 0)
        {
          gvm_json_pull_handle_read_end (parser, event, FALSE);
          return 1;
        }
      else if (parser->last_read_char != keyword[i])
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message =
            g_strdup_printf ("misspelled keyword '%s'", keyword);
          return 1;
        }
      gvm_json_pull_parser_next_char (parser);
    }
  return 0;
}

/**
 * @brief Updates the expectation for a JSON pull parser according to the path.
 *
 * @param[in]  parser  The parser to update.
 */
static void
parse_value_next_expect (gvm_json_pull_parser_t *parser)
{
  if (parser->path->length)
    parser->expect = GVM_JSON_PULL_EXPECT_COMMA;
  else
    parser->expect = GVM_JSON_PULL_EXPECT_EOF;
}

/**
 * @brief Handles the case that an object key is expected in a JSON pull parser.
 *
 * This will continue the parsing until the value is expected, the end of the
 * current object was reached or an error occurred.
 *
 * @param[in]  parser   Parser to process
 * @param[in]  event    Event data to set error or end of object status in
 *
 * @return 1 if an error occurred, 0 otherwise
 */
static int
gvm_json_pull_parse_key (gvm_json_pull_parser_t *parser,
                         gvm_json_pull_event_t *event)
{
  if (gvm_json_pull_skip_space (parser, event, FALSE))
    return 1;

  cJSON *key_cjson = NULL;
  gchar *key_str;
  gvm_json_path_elem_t *path_elem;

  switch (parser->last_read_char)
    {
    case '"':
      if (gvm_json_pull_parse_string (parser, event, &key_cjson))
        return 1;
      key_str = g_strdup (key_cjson->valuestring);
      cJSON_Delete (key_cjson);

      // Expect colon:
      if (gvm_json_pull_skip_space (parser, event, FALSE))
        {
          g_free (key_str);
          return 1;
        }
      if (parser->last_read_char != ':')
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = g_strdup_printf ("expected colon");
          g_free (key_str);
          return 1;
        }
      gvm_json_pull_parser_next_char (parser);

      path_elem = g_queue_peek_tail (parser->path);
      g_free (path_elem->key);
      path_elem->key = key_str;
      parser->expect = GVM_JSON_PULL_EXPECT_VALUE;

      break;
    case '}':
      event->type = GVM_JSON_PULL_EVENT_OBJECT_END;
      event->value = NULL;
      gvm_json_pull_path_elem_free (g_queue_pop_tail (parser->path));
      parse_value_next_expect (parser);
      gvm_json_pull_parser_next_char (parser);
      break;
    case ']':
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      event->error_message = g_strdup ("unexpected closing square bracket");
      return 1;
    default:
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      event->error_message = g_strdup ("unexpected character");
      return 1;
    }

  return 0;
}

/**
 * @brief Handles the case that a comma is expected in a JSON pull parser.
 *
 * This will continue the parsing until a comma or the end of the
 * current array/object was reached or an error occurred.
 *
 * @param[in]  parser   Parser to process
 * @param[in]  event    Event data to set error or end of object status in
 *
 * @return 1 if an error occurred, 0 otherwise
 */
static int
gvm_json_pull_parse_comma (gvm_json_pull_parser_t *parser,
                           gvm_json_pull_event_t *event)
{
  if (gvm_json_pull_skip_space (parser, event, FALSE))
    return 1;

  gvm_json_path_elem_t *path_elem = NULL;
  switch (parser->last_read_char)
    {
    case ',':
      path_elem = g_queue_peek_tail (parser->path);
      path_elem->index++;
      if (path_elem->parent_type == GVM_JSON_PULL_CONTAINER_OBJECT)
        parser->expect = GVM_JSON_PULL_EXPECT_KEY;
      else
        parser->expect = GVM_JSON_PULL_EXPECT_VALUE;
      gvm_json_pull_parser_next_char (parser);
      break;
    case ']':
      path_elem = g_queue_peek_tail (parser->path);
      if (path_elem == NULL
          || path_elem->parent_type != GVM_JSON_PULL_CONTAINER_ARRAY)
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = g_strdup ("unexpected closing square bracket");
          return 1;
        }
      event->type = GVM_JSON_PULL_EVENT_ARRAY_END;
      event->value = NULL;
      gvm_json_pull_path_elem_free (g_queue_pop_tail (parser->path));
      parse_value_next_expect (parser);
      gvm_json_pull_parser_next_char (parser);
      break;
    case '}':
      path_elem = g_queue_peek_tail (parser->path);
      if (path_elem == NULL
          || path_elem->parent_type != GVM_JSON_PULL_CONTAINER_OBJECT)
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = g_strdup ("unexpected closing curly brace");
          return 1;
        }
      event->type = GVM_JSON_PULL_EVENT_OBJECT_END;
      event->value = NULL;
      gvm_json_pull_path_elem_free (g_queue_pop_tail (parser->path));
      parse_value_next_expect (parser);
      gvm_json_pull_parser_next_char (parser);
      break;
    default:
      event->error_message = g_strdup ("expected comma or end of container");
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      return 1;
    }
  return 0;
}

/**
 * @brief Handles the case that a value is expected in a JSON pull parser.
 *
 * This will continue the parsing until a value or the end of the
 * current array/object was parsed or an error occurred.
 *
 * @param[in]  parser   Parser to process
 * @param[in]  event    Event data to set error or end of object status in
 *
 * @return 1 if an error occurred, 0 otherwise
 */
static int
gvm_json_pull_parse_value (gvm_json_pull_parser_t *parser,
                           gvm_json_pull_event_t *event)
{
  if (gvm_json_pull_skip_space (parser, event, FALSE))
    return 1;

  cJSON *cjson_value = NULL;
  gvm_json_path_elem_t *path_elem = NULL;

  switch (parser->last_read_char)
    {
    case '"':
      if (gvm_json_pull_parse_string (parser, event, &cjson_value))
        return 1;
      event->type = GVM_JSON_PULL_EVENT_STRING;
      event->value = cjson_value;
      parse_value_next_expect (parser);
      break;
    case 'n':
      if (gvm_json_pull_parse_keyword (parser, event, "null"))
        return 1;
      event->type = GVM_JSON_PULL_EVENT_NULL;
      event->value = cJSON_CreateNull ();
      parse_value_next_expect (parser);
      break;
    case 'f':
      if (gvm_json_pull_parse_keyword (parser, event, "false"))
        return 1;
      event->type = GVM_JSON_PULL_EVENT_BOOLEAN;
      event->value = cJSON_CreateFalse ();
      parse_value_next_expect (parser);
      break;
    case 't':
      if (gvm_json_pull_parse_keyword (parser, event, "true"))
        return 1;
      event->type = GVM_JSON_PULL_EVENT_BOOLEAN;
      event->value = cJSON_CreateTrue ();
      parse_value_next_expect (parser);
      break;
    case '[':
      event->type = GVM_JSON_PULL_EVENT_ARRAY_START;
      event->value = NULL;
      parser->path_add = gvm_json_pull_path_elem_new (
        GVM_JSON_PULL_CONTAINER_ARRAY, parser->path->length);
      parser->expect = GVM_JSON_PULL_EXPECT_VALUE;
      gvm_json_pull_parser_next_char (parser);
      break;
    case ']':
      path_elem = g_queue_peek_tail (parser->path);
      if (path_elem == NULL
          || path_elem->parent_type != GVM_JSON_PULL_CONTAINER_ARRAY)
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = g_strdup ("unexpected closing square bracket");
          return 1;
        }
      event->type = GVM_JSON_PULL_EVENT_ARRAY_END;
      event->value = NULL;
      gvm_json_pull_path_elem_free (g_queue_pop_tail (parser->path));
      parse_value_next_expect (parser);
      gvm_json_pull_parser_next_char (parser);
      break;
    case '{':
      event->type = GVM_JSON_PULL_EVENT_OBJECT_START;
      event->value = NULL;
      parser->path_add = gvm_json_pull_path_elem_new (
        GVM_JSON_PULL_CONTAINER_OBJECT, parser->path->length);
      parser->expect = GVM_JSON_PULL_EXPECT_KEY;
      gvm_json_pull_parser_next_char (parser);
      break;
    case '}':
      event->type = GVM_JSON_PULL_EVENT_ERROR;
      event->error_message = g_strdup ("unexpected closing curly brace");
      return 1;
      break;
    default:
      if (g_ascii_isdigit (parser->last_read_char)
          || parser->last_read_char == '-')
        {
          if (gvm_json_pull_parse_number (parser, event, &cjson_value))
            return 1;
          event->type = GVM_JSON_PULL_EVENT_NUMBER;
          event->value = cjson_value;
          parse_value_next_expect (parser);
        }
      else
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = g_strdup ("unexpected character");
          return 1;
        }
    }
  return 0;
}

/**
 * @brief Get the next event from a JSON pull parser.
 *
 * Note: This invalidates previous event data like the cJSON value.
 *
 * @param[in]   parser  The JSON pull parser to process until the next event
 * @param[in]   event   Structure to store event data in.
 */
void
gvm_json_pull_parser_next (gvm_json_pull_parser_t *parser,
                           gvm_json_pull_event_t *event)
{
  assert (parser);
  assert (event);

  gvm_json_pull_event_cleanup (event);
  if (parser->last_read_char == GVM_JSON_CHAR_UNDEFINED)
    {
      // Handle first read of the stream
      if (gvm_json_pull_parser_next_char (parser) < 0)
        {
          gvm_json_pull_handle_read_end (parser, event, TRUE);
          return;
        }
    }

  event->path = parser->path;

  // Delayed addition to path after a container start element
  if (parser->path_add)
    {
      g_queue_push_tail (parser->path, parser->path_add);
      parser->path_add = NULL;
    }

  // Check for expected end of file
  if (parser->expect == GVM_JSON_PULL_EXPECT_EOF)
    {
      gvm_json_pull_skip_space (parser, event, TRUE);

      if (parser->last_read_char == GVM_JSON_CHAR_ERROR)
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = gvm_json_read_stream_error_str ();
        }
      else if (parser->last_read_char != GVM_JSON_CHAR_EOF)
        {
          event->type = GVM_JSON_PULL_EVENT_ERROR;
          event->error_message = g_strdup_printf (
            "unexpected character at end of file (%d)", parser->last_read_char);
          return;
        }
      return;
    }

  if (parser->expect == GVM_JSON_PULL_EXPECT_COMMA)
    {
      if (gvm_json_pull_parse_comma (parser, event))
        return;
    }

  if (parser->expect == GVM_JSON_PULL_EXPECT_KEY)
    {
      if (gvm_json_pull_parse_key (parser, event))
        return;
    }

  if (parser->expect == GVM_JSON_PULL_EXPECT_VALUE)
    {
      gvm_json_pull_parse_value (parser, event);
    }
}

/**
 * @brief Expands the current array or object of a JSON pull parser.
 *
 * This should be called after an array or object start event.
 *
 * @param[in]  parser         Parser to get the current container element from
 * @param[out] error_message  Error message output
 *
 * @return The expanded container as a cJSON object if successful, else NULL
 */
cJSON *
gvm_json_pull_expand_container (gvm_json_pull_parser_t *parser,
                                gchar **error_message)
{
  gvm_json_path_elem_t *path_tail = NULL;

  int start_depth;
  gboolean in_string, escape_next_char, in_expanded_container;
  cJSON *expanded;

  g_string_truncate (parser->parse_buffer, 0);

  if (error_message)
    *error_message = NULL;

  // require "path_add" to only allow expansion at start of container
  if (parser->path_add)
    {
      path_tail = parser->path_add;
      g_queue_push_tail (parser->path, path_tail);
      parser->path_add = NULL;
    }

  if (path_tail && path_tail->parent_type == GVM_JSON_PULL_CONTAINER_ARRAY)
    g_string_append_c (parser->parse_buffer, '[');
  else if (path_tail
           && path_tail->parent_type == GVM_JSON_PULL_CONTAINER_OBJECT)
    g_string_append_c (parser->parse_buffer, '{');
  else
    {
      if (error_message)
        *error_message =
          g_strdup ("can only expand after array or object start");
      return NULL;
    }

  start_depth = path_tail->depth;
  in_string = escape_next_char = FALSE;
  in_expanded_container = TRUE;

  while (parser->last_read_char >= 0 && in_expanded_container)
    {
      if (parser->parse_buffer->len >= parser->parse_buffer_limit)
        {
          if (error_message)
            *error_message =
              g_strdup_printf ("container exceeds size limit of %zu bytes",
                               parser->parse_buffer_limit);
          return NULL;
        }

      g_string_append_c (parser->parse_buffer, parser->last_read_char);

      if (escape_next_char)
        {
          escape_next_char = FALSE;
        }
      else if (in_string)
        {
          escape_next_char = (parser->last_read_char == '\\');
          in_string = (parser->last_read_char != '"');
        }
      else
        {
          switch (parser->last_read_char)
            {
            case '"':
              in_string = TRUE;
              break;
            case '[':
              path_tail = gvm_json_pull_path_elem_new (
                GVM_JSON_PULL_CONTAINER_ARRAY, parser->path->length);
              g_queue_push_tail (parser->path, path_tail);
              break;
            case '{':
              path_tail = gvm_json_pull_path_elem_new (
                GVM_JSON_PULL_CONTAINER_OBJECT, parser->path->length);
              g_queue_push_tail (parser->path, path_tail);
              break;
            case ']':
              path_tail = g_queue_pop_tail (parser->path);
              if (path_tail->parent_type != GVM_JSON_PULL_CONTAINER_ARRAY)
                {
                  if (error_message)
                    *error_message =
                      g_strdup ("unexpected closing square bracket");
                  return NULL;
                }
              if (path_tail->depth == start_depth)
                in_expanded_container = FALSE;

              gvm_json_pull_path_elem_free (path_tail);
              break;
            case '}':
              path_tail = g_queue_pop_tail (parser->path);
              if (path_tail->parent_type != GVM_JSON_PULL_CONTAINER_OBJECT)
                {
                  if (error_message)
                    *error_message =
                      g_strdup ("unexpected closing curly brace");
                  return NULL;
                }
              if (path_tail->depth == start_depth)
                in_expanded_container = FALSE;

              gvm_json_pull_path_elem_free (path_tail);
              break;
            }
        }
      gvm_json_pull_parser_next_char (parser);
    }

  if (parser->last_read_char == GVM_JSON_CHAR_ERROR)
    {
      if (error_message)
        *error_message = gvm_json_read_stream_error_str ();
      return NULL;
    }
  else if (in_expanded_container && parser->last_read_char == GVM_JSON_CHAR_EOF)
    {
      if (error_message)
        *error_message = g_strdup ("unexpected EOF");
      return NULL;
    }

  expanded = cJSON_Parse (parser->parse_buffer->str);
  g_string_truncate (parser->parse_buffer, 0);
  parse_value_next_expect (parser);

  if (expanded == NULL && error_message)
    *error_message = g_strdup ("could not parse expanded container");

  return expanded;
}

/**
 * @brief Appends a string path element to a JSONPath string.
 *
 * @param[in]  path_elem    The path element to append
 * @param[in]  path_string  The path string to append to
 */
static void
gvm_json_path_string_add_elem (gvm_json_path_elem_t *path_elem,
                               GString *path_string)
{
  if (path_elem->parent_type == GVM_JSON_PULL_CONTAINER_OBJECT)
    {
      gchar *escaped_key = gvm_json_string_escape (path_elem->key, TRUE);
      g_string_append_printf (path_string, "['%s']", escaped_key);
      g_free (escaped_key);
    }
  else
    g_string_append_printf (path_string, "[%d]", path_elem->index);
}

/**
 * @brief Converts a path as used by a JSON pull parser to a JSONPath string.
 *
 * @param[in]  path   The path to convert
 *
 * @return Newly allocated string of the path in JSONPath bracket notation
 */
gchar *
gvm_json_path_to_string (GQueue *path)
{
  GString *path_string = g_string_new ("$");
  g_queue_foreach (path, (GFunc) gvm_json_path_string_add_elem, path_string);
  return g_string_free (path_string, FALSE);
}
