/* OpenVAS Libraries
 * Copyright (C) 1998 - 2003 Renaud Deraison
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
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * Knowledge base management API
 */

/**
 * @file
 * Knowledge base management API.\n
 * Knowledge bases collect information and can be used to share information
 * between NVTs.\n
 * A knowledge base is an array of knowledge base items (kb_item).
 * An item is defined by its name and has a value (either int or char*), a
 * type flag (indicating whether the value shall be interpreted as int or char*)
 * and a pointer to the "next" item.\n
 * A knowledge base (kb_item**) stores single items at a position according to
 * a hash of the items name (function mkkey). Because of that, a knowledge
 * base has a fixed size of 65537 items and kb_items are implemented as lists.\n
 */

#include <stdlib.h>
#include <string.h>

#include <fnmatch.h>

#include <glib.h>

#include "arglists.h"
#include "kb.h"
#include "system_internal.h"

#define HASH_MAX 65537


/**
 * @brief Creates a hash value for a string to be used as index in a knowledge
 * base array.
 *
 * @param Name string to create hash value for.
 * @return Hash value for string name or 0 if name == NULL.
 */
static unsigned int
mkkey (char *name)
{
  char *p;
  unsigned int h = 0;

  if (name == NULL)
    return 0;

  for (p = name; *p != '\0'; p++)
    h = (h << 3) + (unsigned char) *p;


  return h % HASH_MAX;
}


/**
 * @brief Allocates memory for an array of kb_items with max length of HASH_MAX.
 *
 * @return Pointer to first item in knowledge base item array.
 */
struct kb_item **
kb_new ()
{
  return emalloc (HASH_MAX * sizeof (struct kb_item *));
}


/**
 * @brief READ the knowledge base
 *
 * @return kb_item in knowledge base with name name and type type or NULL if
 *         none found.
 */
struct kb_item *
kb_item_get_single (struct kb_item **kb, char *name, int type)
{
  unsigned int h = mkkey (name);
  struct kb_item *ret;

  if (kb == NULL || name == NULL)
    return NULL;


  ret = kb[h];
  while (ret != NULL)
    {
      if ((strcmp (ret->name, name) == 0) && (type == 0 || (ret->type == type)))
        return ret;
      ret = ret->next;
    }

  return ret;
}


/**
 * @brief Get the value of a kb_item with type KB_TYPE_STR and name name.
 *
 * @return (char*) value of the kb_item name with type KB_TYPE_STR.
 */
char *
kb_item_get_str (struct kb_item **kb, char *name)
{
  struct kb_item *item = kb_item_get_single (kb, name, KB_TYPE_STR);

  if (item == NULL)
    return NULL;
  else
    return item->v.v_str;
}

/**
 * @brief Get the value of a kb_item with type KB_TYPE_INT and name \ref name.
 *
 * @return Value of the kb_item \ref name with type KB_TYPE_INT or -1 if it
 *         does not exist.
 */
int
kb_item_get_int (struct kb_item **kb, char *name)
{
  struct kb_item *item = kb_item_get_single (kb, name, KB_TYPE_INT);
  if (item == NULL)
    return -1;
  else
    return item->v.v_int;
}

/**
 * @brief Returns a list of copies of kb_items with name name in a knowledge base.
 *
 * The result has to be freed (kb_item_get_all_free).
 * Use kb_item_get_pattern if you want to get all items matching a pattern,
 * rather than a single name.
 *
 * @param kb The knowledge base.
 * @param name Name of the item(s) of interest.
 *
 * @return A kb_item list (has to be freed) with kb_items of name name.
 */
struct kb_item *
kb_item_get_all (struct kb_item **kb, char *name)
{
  unsigned h = mkkey (name);
  struct kb_item *k;
  struct kb_item *ret = NULL;

  if (kb == NULL || name == NULL)
    return NULL;

  k = kb[h];
  while (k != NULL)
    {
      if (strcmp (k->name, name) == 0)
        {
          struct kb_item *p;

          p = emalloc (sizeof (struct kb_item));
          memcpy (p, k, sizeof (struct kb_item));
          p->next = ret;
          ret = p;
        }
      k = k->next;
    }
  return ret;
}

/**
 * @brief Returns a list of copies of kb_items that match a pattern.
 *
 * The items have to be freed, e.g. with kb_item_get_all_free.
 *
 * @param kb The knowledge base.
 * @param expr A pattern that can be used with fnmatch (e.g. "www/serv*").
 *
 * @return A list of kb_items (has to be freed) whose name matches the pattern
 *         exp.
 */
struct kb_item *
kb_item_get_pattern (struct kb_item **kb, char *expr)
{
  int i;
  struct kb_item *k;
  struct kb_item *ret = NULL;

  if (kb == NULL)
    return NULL;

  for (i = 0; i < HASH_MAX; i++)
    {
      k = kb[i];
      while (k != NULL)
        {
          if (fnmatch (expr, k->name, 0) == 0)
            {
              struct kb_item *p;
              p = emalloc (sizeof (struct kb_item));
              memcpy (p, k, sizeof (struct kb_item));
              p->next = ret;
              ret = p;
            }
          k = k->next;
        }
    }
  return ret;
}


/**
 * @brief Frees a list of kb_items.
 *
 * Can be used to free the results of querying the kb with kb_item_get_all() or
 * kb_item_get_pattern().
 *
 * @param items The list of kb_items to free.
 */
void
kb_item_get_all_free (struct kb_item *items)
{
  while (items != NULL)
    {
      struct kb_item *next;
      next = items->next;
      memset (items, 0xd7, sizeof (struct kb_item));
      efree (&items);
      items = next;
    }
}


/**
 * @brief Add a kb_item with type KB_TYPE_STR and value value to the knowledge base.
 *
 * @param kb The knowledge base itself.
 * @param name Name of the item to add.
 * @param value Value of the item to add.
 * @param replace 0 if an existing item should NOT be replaced (e.g. to create
 *                lists), different than 0 if the value of an existing item with
 *                that name shall be replaced.
 *
 * @return -1 if kb equals NULL or if an item as wished exists already, 0 if
 *         success.
 */
static int
kb_item_addset_str (struct kb_item **kb, char *name, char *value, int replace)
{
  /* Before we write anything to the KB, we need to make sure that the same
   * (name,value) pair is not present already. */
  int h = mkkey (name);
  struct kb_item *item;

  if (kb == NULL)
    return -1;

  item = kb[h];

  while (item != NULL)
    {
      if (strcmp (item->name, name) == 0)
        {
          if (item->type == KB_TYPE_STR && strcmp (item->v.v_str, value) == 0)
            return -1;

          if (replace != 0)
            {
              if (item->type == KB_TYPE_STR)
                efree (&item->v.v_str);

              item->type = KB_TYPE_STR;
              item->v.v_str = estrdup (value);
              return 0;
            }
        }

      item = item->next;
    }

  item = emalloc (sizeof (struct kb_item));
  item->name = estrdup (name);
  item->v.v_str = estrdup (value);
  item->type = KB_TYPE_STR;
  item->next = kb[h];
  kb[h] = item;
  return 0;
}

/**
 * @brief Adds a string to the knowledge base.
 * In contrast to kb_item_set_str the item will not be replaced (useful for
 * list creation).
 *
 * @param kb    The knowledge base.
 * @param name  Key of the entry.
 * @param value Value of the entry.
 */
int
kb_item_add_str (struct kb_item **kb, char *name, char *value)
{
  return kb_item_addset_str (kb, name, value, 0);
}

int
kb_item_set_str (struct kb_item **kb, char *name, char *value)
{
  return kb_item_addset_str (kb, name, value, 1);
}

/**
 * @brief Replace an old value in the KB by a new one.
 *
 * @return -1 if kn is NULL or
 */
static int
kb_item_addset_int (struct kb_item **kb, char *name, int value, int replace)
{
  /* Before we write anything to the KB, we need to make sure that the same
   * (name,value) pair is not present already. */
  int h = mkkey (name);
  struct kb_item *item;

  if (kb == NULL)
    return -1;


  item = kb[h];

  while (item != NULL)
    {
      if (strcmp (item->name, name) == 0)
        {
          if (item->type == KB_TYPE_INT && item->v.v_int == value)
            return -1;

          if (replace != 0)
            {
              if (item->type == KB_TYPE_STR)
                efree (&item->v.v_str);

              item->type = KB_TYPE_INT;
              item->v.v_int = value;
              return 0;
            }
        }

      item = item->next;
    }

  item = emalloc (sizeof (struct kb_item));
  item->name = estrdup (name);
  item->v.v_int = value;
  item->type = KB_TYPE_INT;
  item->next = kb[h];
  kb[h] = item;
  return 0;
}


int
kb_item_set_int (struct kb_item **kb, char *name, int value)
{
  return kb_item_addset_int (kb, name, value, 1);
}

int
kb_item_add_int (struct kb_item **kb, char *name, int value)
{
  return kb_item_addset_int (kb, name, value, 0);
}


void
kb_item_rm_all (struct kb_item **kb, char *name)
{
  int h = mkkey (name);
  struct kb_item *k, *prev = NULL;

  if (kb == NULL)
    return;

  k = kb[h];
  while (k != NULL)
    {
      if (strcmp (k->name, name) == 0)
        {
          struct kb_item *next;
          if (k->type == ARG_STRING)
            efree (&k->v.v_str);

          efree (&k->name);
          next = k->next;
          efree (&k);
          if (prev != NULL)
            prev->next = next;
          else
            kb[h] = next;
          k = next;
        }
      else
        {
          prev = k;
          k = k->next;
        }
    }
}
