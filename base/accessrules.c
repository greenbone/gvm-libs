/* OpenVAS: openvas-libraries/base
 * $Id$
 * Description: Implementation of API to handle Access Rules
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
 * @file accessrules.c
 * @brief Implementation of API to handle Access Rules
 *
 * This file contains all methods to handle Access Rule datasets
 * (accessrule_t).
 *
 * The module consequently uses glib datatypes and api for memory
 * management etc.
 */

// for FILE
#include <stdio.h>

#include "accessrules.h"

/**
 * @brief Create a new access rule structure filled with the given values.
 *
 * @return NULL in case the memory could not be allocated.
 *         Else an empty accessrule structure which needs to be
 *         released using @ref accessrule_free .
 *         The whole struct is initalized with 0's.
 */
accessrule_t *
accessrule_new (void)
{
  return ((accessrule_t *) g_malloc0 (sizeof (accessrule_t)));
}

//
/**
 * @brief Free memory of a access rules structure.
 *
 * @param r The structure to be freed.
 */
void
accessrule_free (accessrule_t * r)
{
  if (r->ip)
    g_free (r->ip);
  if (r->comment)
    g_free (r->comment);
  g_free (r);
}

/**
 * @brief Get the rule type.
 *
 * @param r The Access Rule structure of which the rule
 *          should be returned.
 *
 * @return The rule type.
 */
rule_t
accessrule_rule (const accessrule_t * r)
{
  return (r->rule);
}

/**
 * @brief Get the IP string.
 *
 * @param r The Access Rule structure of which the IP should
 *          be returned.
 *
 * @return The IP string. Don't free this.
 */
gchar *
accessrule_ip (const accessrule_t * r)
{
  return (r->ip);
}

/**
 * @brief Get the comment string.
 *
 * @param r The Access Rule structure of which the comment should
 *          be returned.
 *
 * @return The comment string. Don't free this.
 */
gchar *
accessrule_comment (const accessrule_t * r)
{
  return (r->comment);
}

/**
 * @brief Set the rule type of a Access Rule.
 *
 * @param r The Access Rule structure.
 *
 * @param rule The rule type to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
accessrule_set_rule (accessrule_t * r, const rule_t rule)
{
  r->rule = rule;
  return (0);
}

/**
 * @brief Set the IP of a Access Rule.
 *
 * @param r The Access Rule structure.
 *
 * @param ip The IP string to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
accessrule_set_ip (accessrule_t * r, const gchar * ip)
{
  if (r->ip)
    g_free (r->ip);
  r->ip = g_strdup (ip);
  return (0);
}

/**
 * @brief Set the comment of a Access Rule.
 *
 * @param r The Access Rule structure.
 *
 * @param comment The comment string to set. A copy will be created from this.
 *
 * @return 0 for success. Anything else indicates an error.
 */
int
accessrule_set_comment (accessrule_t * r, const gchar * comment)
{
  if (r->comment)
    g_free (r->comment);
  r->comment = g_strdup (comment);
  return (0);
}

/**
 * @brief Create a XML representation of a Access Rule.
 *
 * @param r The Access Rule structure.
 *
 * @return A newly allocated string with multi-line text.
 *         The string needs to be freed with g_free().
 */
gchar *
accessrule_as_xml (const accessrule_t * r)
{
  /** @TODO Use g_markup_escape here */
  return (g_strconcat
          ("<accessrule>", "<rule>", (r->rule == ALLOW ? "allow" : "reject"),
           "</rule>", (r->ip ? "<ip>" : ""), (r->ip ? r->ip : ""),
           (r->ip ? "</ip>" : ""), (r->comment ? "<comment>" : ""),
           (r->comment ? r->comment : ""), (r->comment ? "</comment>" : ""),
           "</accessrule>", NULL));
}


/* Collections of Access Rules. */

/**
 * @brief Free an Access Rule, for g_hash_table_destroy.
 *
 * @param r The Access Rule.
 */
static void
free_accessrule_for_hash_table (gpointer r)
{
  accessrule_free ((accessrule_t *) r);
}

/**
 * @brief Make a collection of Access Rules.
 */
accessrules_t *
accessrules_new ()
{
  return g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
                                free_accessrule_for_hash_table);
}

/**
 * @brief Free a collection of Access Rules.
 *
 * @param rules The collection of Access Rules.
 */
void
accessrules_free (accessrules_t * rules)
{
  if (rules)
    g_hash_table_destroy (rules);
}

/**
 * @brief Get the size of a collection of Access Rules.
 *
 * @return The number of entries in the collection.
 */
guint
accessrules_size (accessrules_t * rules)
{
  return g_hash_table_size (rules);
}

/**
 * @brief Add an Access Rule to a collection of Access Rules.
 *
 * @param rules The collection of Access Rules (must have ip set).
 */
void
accessrules_add (accessrules_t * rules, accessrule_t * r)
{
  if (r && accessrule_ip (r))
    g_hash_table_insert (rules, (gpointer) accessrule_ip (r), (gpointer) r);
}

/**
 * @brief Handle the start of an xml element in an accessrule xml file.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  attribute_names   XML attribute name.
 * @param[in]  attribute_values  XML attribute values.
 * @param[in]  user_data         Not used.
 * @param[in]  error             Error parameter.
 */
static void
handle_start_element (GMarkupParseContext * context, const gchar * element_name,
                      const gchar ** attribute_names,
                      const gchar ** attribute_values, gpointer user_data,
                      GError ** error)
{
  // Can be:
  // <accessrules>
  // <accessrule>
  // <rule>
  // <ip>
  // <comment>
}

/**
 * @brief Handle the end of an xml element in an accessrule xml file.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Not used.
 * @param[in]  error             Error parameter.
 */
static void
handle_end_element (GMarkupParseContext * context, const gchar * element_name,
                    gpointer user_data, GError ** error)
{

}

/**
 * @brief Handle additional text of an XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Not used.
 * @param[in]  error             Error parameter.
 */
static void
handle_text (GMarkupParseContext * context, const gchar * text, gsize text_len,
             gpointer user_data, GError ** error)
{

}

/**
 * @brief Handle an XML parsing error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
static void
handle_error (GMarkupParseContext * context, GError * error, gpointer user_data)
{

}

/**
 * @brief Read a collection of Access Rules from a file.
 *
 * @param fn The filename from which to read.
 *
 * @return NULL in case an error occured. Else a collection of access rules
 *         which might be empty e.g. if the format was incorrect.
 */
accessrules_t *
accessrules_from_file (gchar * fn)
{
  GMarkupParser xml_parser;
  GError *error = NULL;
  GMarkupParseContext *context;
  gchar *file_contents;

  /* Set up the XML parser. */
  xml_parser.start_element = handle_start_element;
  xml_parser.end_element = handle_end_element;
  xml_parser.text = handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = handle_error;

  /** @TODO Create a access_rules_t* and pass as user data */
  context = g_markup_parse_context_new (&xml_parser, 0, NULL, NULL);

  /** @TODO error checks, handling */
  if (g_file_get_contents (fn, &file_contents, NULL, &error) == FALSE)
    ;
  if (g_markup_parse_context_parse
      (context, file_contents, strlen (file_contents), error) == FALSE)
    ;

  return NULL;
}

/**
 * @brief g_hash_table callback function to print the results of @ref
 * @brief accessrule_as_xml to file @ref file in a g_hash_table_foreach.
 * 
 * @param ip   (Ignored) The ip for the rule (key in the g_hashtable).
 * @param rule The rule itself (value in the g_hashtable).
 * @param file File handle to write to.
 */
static void
accessrule_to_file (gchar * ip, accessrule_t * rule, FILE * file)
{
  if (!file || !rule)
    return;

  gchar *rule_as_xml = accessrule_as_xml (rule);
  if (rule_as_xml)
    {
      fprintf (file, "%s", rule_as_xml);
      g_free (rule_as_xml);
    }

  return;
}

/**
 * @brief Write the contents of a Access Rules collection to a file.
 *
 * @param rules The collection of Access Rules.
 * @param fn    The filename where to store the Access Rules.
 *
 * @return 0 in case of success, other values mean a failure.
 */
guint
accessrules_to_file (accessrules_t * rules, gchar * fn)
{
  FILE *fp;

  if ((!rules) || (!fn))
    return 1;

  fp = fopen (fn, "w");
  if (!fp)
    return NULL;

  fprintf (fp, "<acessrules>\n");
  g_hash_table_foreach (rules, accessrule_to_file, fp);
  fprintf (fp, "</acessrules>\n");

  fclose (fp);
  return 0;
}
