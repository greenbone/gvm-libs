/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "jsonpull.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (jsonpull);
BeforeEach (jsonpull)
{
}
AfterEach (jsonpull)
{
}


/*
 * Helper function to open a string as a read-only stream.
 */
static inline FILE *
fstropen_r (const char *str)
{
  return fmemopen ((void*)str, strlen(str), "r");
}

#define INIT_JSON_PARSER(json_string)                                 \
  gvm_json_pull_event_t event;                                        \
  gvm_json_pull_parser_t parser;                                      \
  FILE *jsonstream;                                                   \
  jsonstream = fstropen_r (json_string);                              \
  gvm_json_pull_event_init (&event);                                  \
  gvm_json_pull_parser_init_full (&parser, jsonstream, 100, 4);

#define CLEANUP_JSON_PARSER \
  gvm_json_pull_event_cleanup (&event);                               \
  gvm_json_pull_parser_cleanup (&parser);                             \
  fclose (jsonstream);                                                \

#define CHECK_PATH_EQUALS(expected_path_str) \
  path_str = gvm_json_path_to_string (event.path);                    \
  assert_that (path_str, is_equal_to_string (expected_path_str));     \
  g_free (path_str);

Ensure (jsonpull, can_json_escape_strings)
{
  const char *unescaped_string = "\"'Abc\\\b\f\n\r\t\001Äöü'\"";
  const char *escaped_string_dq = "\\\"'Abc\\\\\\b\\f\\n\\r\\t\\u0001Äöü'\\\"";
  const char *escaped_string_sq = "\"\\'Abc\\\\\\b\\f\\n\\r\\t\\u0001Äöü\\'\"";

  gchar *escaped_string = NULL;
  escaped_string = gvm_json_string_escape (NULL, FALSE);
  assert_that (escaped_string, is_null);

  escaped_string = gvm_json_string_escape (unescaped_string, FALSE);
  assert_that (escaped_string, is_equal_to_string (escaped_string_dq));
  g_free (escaped_string);

  escaped_string = gvm_json_string_escape (unescaped_string, TRUE);
  assert_that (escaped_string, is_equal_to_string (escaped_string_sq));
  g_free (escaped_string);
}

Ensure (jsonpull, can_init_parser_with_defaults)
{
  gvm_json_pull_parser_t parser;
  FILE *strfile = fstropen_r ("[]");
  
  gvm_json_pull_parser_init (&parser, strfile);
  assert_that (parser.input_stream, is_equal_to (strfile));
  assert_that (parser.parse_buffer_limit,
               is_equal_to (GVM_JSON_PULL_PARSE_BUFFER_LIMIT));
  assert_that (parser.read_buffer_size,
               is_equal_to (GVM_JSON_PULL_READ_BUFFER_SIZE));
}

Ensure (jsonpull, can_parse_false)
{
  INIT_JSON_PARSER ("false");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_BOOLEAN));
  assert_that (cJSON_IsBool (event.value), is_true);
  assert_that (cJSON_IsFalse (event.value), is_true);

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_true)
{
  INIT_JSON_PARSER ("true");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_BOOLEAN));
  assert_that (cJSON_IsBool (event.value), is_true);
  assert_that (cJSON_IsTrue (event.value), is_true);

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_null)
{
  INIT_JSON_PARSER ("null");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NULL));
  assert_that (cJSON_IsNull (event.value), is_true);

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_empty_strings)
{
  INIT_JSON_PARSER ("\"\"")

  gvm_json_pull_parser_next (&parser, &event);                       
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_STRING));
  assert_that (event.value->valuestring, is_equal_to_string (""));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_strings_with_content)
{
  INIT_JSON_PARSER ("\n\"123\\tXYZ\\nÄöü\"\n")

  gvm_json_pull_parser_next (&parser, &event);                       
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_STRING));
  assert_that (event.value->valuestring,
               is_equal_to_string ("123\tXYZ\nÄöü"));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_integer_numbers)
{
  INIT_JSON_PARSER ("-0987")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (-987));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_floating_point_numbers)
{
  INIT_JSON_PARSER ("\t\n 1.2345e+4\n");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valuedouble, is_equal_to (1.2345e+4));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_empty_arrays)
{
  INIT_JSON_PARSER ("[   ]");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_single_elem_arrays)
{
  gchar *path_str;
  INIT_JSON_PARSER ("[ 123 ]");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (123));
  CHECK_PATH_EQUALS ("$[0]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_multiple_elem_arrays)
{
  gchar *path_str;
  INIT_JSON_PARSER ("[123, \"ABC\", null]");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (123));
  CHECK_PATH_EQUALS ("$[0]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_STRING));
  assert_that (event.value->valuestring, is_equal_to_string ("ABC"));
  CHECK_PATH_EQUALS ("$[1]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NULL));
  CHECK_PATH_EQUALS ("$[2]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_empty_objects)
{
  INIT_JSON_PARSER ("{   }");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_END));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_single_elem_objects)
{
  gchar *path_str;
  INIT_JSON_PARSER ("{ \"keyA\": \"valueA\" }");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_STRING));
  assert_that (event.value->valuestring, is_equal_to_string ("valueA"));
  CHECK_PATH_EQUALS ("$['keyA']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_END));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_multiple_elem_objects)
{
  gchar *path_str;
  INIT_JSON_PARSER ("{ \"keyA\": \"valueA\", \"keyB\":12345 }");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_STRING));
  assert_that (event.value->valuestring, is_equal_to_string ("valueA"));
  CHECK_PATH_EQUALS ("$['keyA']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (12345));
  CHECK_PATH_EQUALS ("$['keyB']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_END));

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_parse_nested_containers)
{
  gchar *path_str;
  INIT_JSON_PARSER ("[{\"A\":null, \"B\":{\"C\": [1,2]}, \"D\":\"3\"}, [4]]");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$")
  
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));
  CHECK_PATH_EQUALS ("$[0]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NULL));
  CHECK_PATH_EQUALS ("$[0]['A']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));
  CHECK_PATH_EQUALS ("$[0]['B']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$[0]['B']['C']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (1));
  CHECK_PATH_EQUALS ("$[0]['B']['C'][0]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (2));
  CHECK_PATH_EQUALS ("$[0]['B']['C'][1]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));
  CHECK_PATH_EQUALS ("$[0]['B']['C']")
  
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_END));
  CHECK_PATH_EQUALS ("$[0]['B']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_STRING));
  assert_that (event.value->valuestring, is_equal_to_string ("3"));
  CHECK_PATH_EQUALS ("$[0]['D']")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_END));
  CHECK_PATH_EQUALS ("$[0]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$[1]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_NUMBER));
  assert_that (event.value->valueint, is_equal_to (4));
  CHECK_PATH_EQUALS ("$[1][0]")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));
  CHECK_PATH_EQUALS ("$[1]")
  
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));
  CHECK_PATH_EQUALS ("$")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_expand_arrays)
{
  gchar *path_str, *error_message;
  cJSON *expanded, *child;
  INIT_JSON_PARSER ("[[], [1], [2, [3]], [\"A\", \"\\\"B]\"]]");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$")

  // empty array
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$[0]")
  expanded = gvm_json_pull_expand_container (&parser, &error_message);
  assert_that (error_message, is_equal_to_string (NULL));
  assert_that (expanded, is_not_null);
  assert_that (cJSON_IsArray (expanded), is_true);
  assert_that (expanded->child, is_null);
  cJSON_free (expanded);

  // single-element array
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$[1]")
  expanded = gvm_json_pull_expand_container (&parser, &error_message);
  assert_that (error_message, is_null);
  assert_that (expanded, is_not_null);
  assert_that (cJSON_IsArray (expanded), is_true);
  child = expanded->child;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsNumber(child), is_true);
  assert_that (child->valueint, is_equal_to(1));
  child = child->next;
  assert_that (child, is_null);
  cJSON_free (expanded);
  
  // multi-element array
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$[2]")
  expanded = gvm_json_pull_expand_container (&parser, &error_message);
  assert_that (error_message, is_null);
  assert_that (expanded, is_not_null);
  assert_that (cJSON_IsArray (expanded), is_true);
  child = expanded->child;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsNumber(child), is_true);
  assert_that (child->valueint, is_equal_to(2));
  child = child->next;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsArray(child), is_true);
  assert_that (child->child->valueint, is_equal_to(3));
  cJSON_free (expanded);
  
  // string array
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_START));
  CHECK_PATH_EQUALS ("$[3]")
  expanded = gvm_json_pull_expand_container (&parser, &error_message);
  assert_that (error_message, is_null);
  assert_that (expanded, is_not_null);
  assert_that (cJSON_IsArray (expanded), is_true);
  child = expanded->child;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsString(child), is_true);
  assert_that (child->valuestring, is_equal_to_string("A"));
  child = child->next;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsString(child), is_true);
  assert_that (child->valuestring, is_equal_to_string("\"B]"));
  cJSON_free (expanded);

  // array end and EOF
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_ARRAY_END));
  CHECK_PATH_EQUALS ("$")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}

Ensure (jsonpull, can_expand_objects)
{
  gchar *path_str, *error_message;
  cJSON *expanded, *child;
  INIT_JSON_PARSER (
    "{\"A\":{}, \"B\": {\"C\": \"\\\"D}\", \"E\":123, \"F\":{}}}");

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));
  CHECK_PATH_EQUALS ("$")
  
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));
  CHECK_PATH_EQUALS ("$['A']")
  expanded = gvm_json_pull_expand_container (&parser, &error_message);
  assert_that (error_message, is_null);
  assert_that (cJSON_IsObject (expanded), is_true);
  assert_that (expanded->child, is_null);
  cJSON_free (expanded);

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_START));
  CHECK_PATH_EQUALS ("$['B']")
  expanded = gvm_json_pull_expand_container (&parser, &error_message);
  assert_that (error_message, is_null);
  assert_that (cJSON_IsObject (expanded), is_true);
  child = expanded->child;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsString(child), is_true);
  assert_that (child->string, is_equal_to_string ("C"));
  assert_that (child->valuestring, is_equal_to_string ("\"D}"));
  child = child->next;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsNumber(child), is_true);
  assert_that (child->string, is_equal_to_string ("E"));
  assert_that (child->valueint, is_equal_to (123));
  child = child->next;
  assert_that (child, is_not_null);
  assert_that (cJSON_IsObject(child), is_true);
  assert_that (child->string, is_equal_to_string ("F"));
  assert_that (child->child, is_null);
  cJSON_free (expanded);

  // object end and EOF
  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_OBJECT_END));
  CHECK_PATH_EQUALS ("$")

  gvm_json_pull_parser_next (&parser, &event);
  assert_that (event.type, is_equal_to (GVM_JSON_PULL_EVENT_EOF));
  CLEANUP_JSON_PARSER
}


int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, jsonpull, can_json_escape_strings);

  add_test_with_context (suite, jsonpull, can_init_parser_with_defaults);

  add_test_with_context (suite, jsonpull, can_parse_false);
  add_test_with_context (suite, jsonpull, can_parse_true);
  add_test_with_context (suite, jsonpull, can_parse_null);
  
  add_test_with_context (suite, jsonpull, can_parse_empty_strings);
  add_test_with_context (suite, jsonpull, can_parse_strings_with_content);

  add_test_with_context (suite, jsonpull, can_parse_integer_numbers);
  add_test_with_context (suite, jsonpull, can_parse_floating_point_numbers);

  add_test_with_context (suite, jsonpull, can_parse_empty_arrays);
  add_test_with_context (suite, jsonpull, can_parse_single_elem_arrays);
  add_test_with_context (suite, jsonpull, can_parse_multiple_elem_arrays);

  add_test_with_context (suite, jsonpull, can_parse_empty_objects);
  add_test_with_context (suite, jsonpull, can_parse_single_elem_objects);
  add_test_with_context (suite, jsonpull, can_parse_multiple_elem_objects);
  add_test_with_context (suite, jsonpull, can_parse_nested_containers);
  add_test_with_context (suite, jsonpull, can_expand_arrays);
  add_test_with_context (suite, jsonpull, can_expand_objects);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());
  return run_test_suite (suite, create_text_reporter ());
}