/* SPDX-FileCopyrightText: 2009-2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Functions to convert different CPE notations into each other.
 *
 * This library provides functions to read the CPE 2.2 URI binding of a
 * CPE or the CPE 2.3 formatted string binding of a CPE into a CPE struct
 * that corresponds to the WFN naming of a CPE. Further functions to convert
 * the CPE struct into the different bindings are provided.
 * This file also contains a function that checks if one CPE (represented in a
 * CPE struct) is a match for an other CPE (also represented in a CPE struct).
 */

#include "cpeutils.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <glib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

static enum set_relation
compare_component (const char *, const char *);

static enum set_relation
compare_strings (const char *, const char *);

static int
count_escapes (const char *, int, int);

static gboolean
is_even_wildcards (const char *, int);

static gboolean
has_wildcards (const char *);

static int
index_of (const char *, const char *, int);

static gboolean
is_string (const char *);

static char *
get_uri_component (const char *, int);

static char *
decode_uri_component (const char *);

static void
unpack_sixth_uri_component (const char *, cpe_struct_t *);

static char *
get_fs_component (const char *, int);

static char *
unbind_fs_component (char *);

static char *
add_quoting (const char *);

static char *
bind_cpe_component_for_uri (const char *);

static char *
transform_for_uri (const char *);

static char *
pack_sixth_uri_component (const cpe_struct_t *);

static char *
bind_cpe_component_for_fs (const char *);

static char *
process_quoted_chars (const char *);

static void
trim_pct (char *);

static void
get_code (char *, const char *);

static void
str_cpy (char **, const char *, int);

/**
 * @brief Convert a URI CPE to a formatted string CPE.
 *
 * @param[in]  uri_cpe  A CPE v2.2-conformant URI.
 *
 * @return  A formatted string CPE.
 */
char *
uri_cpe_to_fs_cpe (const char *uri_cpe)
{
  cpe_struct_t cpe;
  char *fs_cpe;

  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  fs_cpe = cpe_struct_to_fs_cpe (&cpe);
  cpe_struct_free (&cpe);
  return (fs_cpe);
}

/**
 * @brief Convert a URI CPE to a formatted string product.
 *
 * @param[in]  uri_cpe  A CPE v2.2-conformant URI.
 *
 * @return  A formatted string product.
 */
char *
uri_cpe_to_fs_product (const char *uri_cpe)
{
  cpe_struct_t cpe;
  char *fs_cpe;

  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  fs_cpe = cpe_struct_to_fs_product (&cpe);
  cpe_struct_free (&cpe);
  return (fs_cpe);
}

/**
 * @brief Convert a formatted string CPE to a URI CPE.
 *
 * @param[in]  fs_cpe  A formatted string CPE.
 *
 * @return  A CPE v2.2-conformant URI.
 */
char *
fs_cpe_to_uri_cpe (const char *fs_cpe)
{
  cpe_struct_t cpe;
  char *uri_cpe;

  cpe_struct_init (&cpe);
  fs_cpe_to_cpe_struct (fs_cpe, &cpe);
  uri_cpe = cpe_struct_to_uri_cpe (&cpe);
  cpe_struct_free (&cpe);
  return (uri_cpe);
}

/**
 * @brief Convert a formatted string CPE to an URI product.
 *
 * @param[in]  fs_cpe  A formatted string CPE.
 *
 * @return  An URI product.
 */
char *
fs_cpe_to_uri_product (const char *fs_cpe)
{
  cpe_struct_t cpe;
  char *uri_cpe;

  cpe_struct_init (&cpe);
  fs_cpe_to_cpe_struct (fs_cpe, &cpe);
  uri_cpe = cpe_struct_to_uri_product (&cpe);
  cpe_struct_free (&cpe);
  return (uri_cpe);
}

/**
 * @brief Read a URI CPE into the CPE struct.
 *
 * @param[in]   uri_cpe  A CPE v2.2-conformant URI.
 *
 * @param[out]  cpe      Pointer to the filled CPE struct.
 */
void
uri_cpe_to_cpe_struct (const char *uri_cpe, cpe_struct_t *cpe)
{
  char *uri_component;

  uri_component = get_uri_component (uri_cpe, 1);
  cpe->part = decode_uri_component (uri_component);
  g_free (uri_component);
  uri_component = get_uri_component (uri_cpe, 2);
  cpe->vendor = decode_uri_component (uri_component);
  g_free (uri_component);
  uri_component = get_uri_component (uri_cpe, 3);
  cpe->product = decode_uri_component (uri_component);
  g_free (uri_component);
  uri_component = get_uri_component (uri_cpe, 4);
  cpe->version = decode_uri_component (uri_component);
  g_free (uri_component);
  uri_component = get_uri_component (uri_cpe, 5);
  cpe->update = decode_uri_component (uri_component);
  g_free (uri_component);
  uri_component = get_uri_component (uri_cpe, 6);
  if (strcmp (uri_component, "") == 0 || strcmp (uri_component, "-") == 0
      || *uri_component != '~')
    cpe->edition = decode_uri_component (uri_component);
  else
    unpack_sixth_uri_component (uri_component, cpe);
  g_free (uri_component);

  uri_component = get_uri_component (uri_cpe, 7);
  cpe->language = decode_uri_component (uri_component);
  g_free (uri_component);
}

/**
 * @brief Convert a CPE struct into a URI CPE.
 *
 * @param[in]   cpe  A pointer to the CPE struct.
 *
 * @return  A CPE v2.2-conformant URI.
 */
char *
cpe_struct_to_uri_cpe (const cpe_struct_t *cpe)
{
  GString *uri_cpe;
  char *bind_cpe_component;
  uri_cpe = g_string_new ("cpe:/");

  bind_cpe_component = bind_cpe_component_for_uri (cpe->part);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->vendor);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->product);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->version);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->update);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = pack_sixth_uri_component (cpe);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->language);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }

  char *result = g_string_free (uri_cpe, FALSE);
  trim_pct (result);
  return (result);
}

/**
 * @brief Convert a CPE struct into a URI product.
 *
 * @param[in]   cpe  A pointer to the CPE struct.
 *
 * @return  A CPE v2.2-conformant URI product.
 */
char *
cpe_struct_to_uri_product (const cpe_struct_t *cpe)
{
  GString *uri_cpe;
  char *bind_cpe_component;
  uri_cpe = g_string_new ("cpe:/");

  bind_cpe_component = bind_cpe_component_for_uri (cpe->part);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->vendor);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_uri (cpe->product);
  if (bind_cpe_component)
    {
      g_string_append_printf (uri_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }

  char *result = g_string_free (uri_cpe, FALSE);
  trim_pct (result);
  return (result);
}

/**
 * @brief Read a formatted string CPE into the CPE struct.
 *
 * @param[in]   fs_cpe  A formatted string CPE.
 *
 * @param[out]  cpe     Pointer to the filled CPE struct.
 */
void
fs_cpe_to_cpe_struct (const char *fs_cpe, cpe_struct_t *cpe)
{
  char *fs_component;

  fs_component = get_fs_component (fs_cpe, 2);
  cpe->part = unbind_fs_component (fs_component);
  fs_component = get_fs_component (fs_cpe, 3);
  cpe->vendor = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 4);
  cpe->product = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 5);
  cpe->version = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 6);
  cpe->update = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 7);
  cpe->edition = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 8);
  cpe->language = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 9);
  cpe->sw_edition = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 10);
  cpe->target_sw = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 11);
  cpe->target_hw = unbind_fs_component (fs_component);
  g_free (fs_component);
  fs_component = get_fs_component (fs_cpe, 12);
  cpe->other = unbind_fs_component (fs_component);
  g_free (fs_component);
}

/**
 * @brief Convert a CPE struct into a formatted string CPE.
 *
 * @param[in]   cpe  A pointer to the CPE struct.
 *
 * @return  A formatted string CPE.
 */
char *
cpe_struct_to_fs_cpe (const cpe_struct_t *cpe)
{
  GString *fs_cpe;
  char *bind_cpe_component;

  fs_cpe = g_string_new ("cpe:2.3:");

  bind_cpe_component = bind_cpe_component_for_fs (cpe->part);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->vendor);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->product);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->version);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->update);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->edition);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->language);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->sw_edition);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->target_sw);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->target_hw);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->other);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  return (g_string_free (fs_cpe, FALSE));
}

/**
 * @brief Convert a CPE struct into a formatted string product.
 *
 * @param[in]   cpe  A pointer to the CPE struct.
 *
 * @return  A formatted string product.
 */
char *
cpe_struct_to_fs_product (const cpe_struct_t *cpe)
{
  GString *fs_cpe;
  char *bind_cpe_component;

  fs_cpe = g_string_new ("cpe:2.3:");

  bind_cpe_component = bind_cpe_component_for_fs (cpe->part);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->vendor);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  bind_cpe_component = bind_cpe_component_for_fs (cpe->product);
  if (bind_cpe_component)
    {
      g_string_append_printf (fs_cpe, "%s:", bind_cpe_component);
      g_free (bind_cpe_component);
    }
  return (g_string_free (fs_cpe, FALSE));
}

/**
 * @brief Get the indexth component of a URI CPE.
 *
 * @param[in]   uri_cpe  The URI CPE.
 * @param[in]   index    The number of the component to get.
 *
 * @return  The indexth component of the URI CPE.
 */
static char *
get_uri_component (const char *uri_cpe, int index)
{
  char *component = NULL;
  char *c;
  char *component_start, *component_end;

  if (!uri_cpe)
    return NULL;

  c = (char *) uri_cpe;

  /* find start of component */
  for (int i = 0; *c != '\0' && i < index; c++)
    {
      if (*c == ':')
        i++;
    }

  if (index == 1 && *c != '\0')
    c++;

  component_start = c;

  /* find end of component */
  if (*component_start == '\0')
    component_end = component_start;
  else
    {
      for (c = component_start; *c != '\0' && *c != ':'; c++)
        ;
    }

  component_end = c;

  if (component_start >= component_end || component_end == 0)
    component = (char *) g_strdup ("");
  else
    str_cpy (&component, component_start, component_end - component_start);

  return component;
}

/**
 * @brief Decode a component of a URI CPE.
 *
 * @param[in]  component  The component to decode.
 *
 * @return  The decoded component of the URI CPE.
 */
static char *
decode_uri_component (const char *component)
{
  GString *decoded_component;
  char *escapes = "!\"#$%&'()*+,/:;<=>?@[\\]^`{|}~";
  char *tmp_component;
  char code_a[4], code_b[4], code_c[4];
  long unsigned int index;
  gboolean embedded;

  if (!component)
    return (NULL);

  if (strcmp (component, "") == 0 || strcmp (component, " ") == 0)
    {
      return (g_strdup ("ANY"));
    }
  if (strcmp (component, "-") == 0)
    {
      return (g_strdup ("NA"));
    }

  tmp_component = g_strdup (component);

  /* set all characters to lowercase */
  char *c = tmp_component;
  for (; *c; c++)
    *c = tolower (*c);

  index = 0;
  embedded = FALSE;
  decoded_component = g_string_new ("");

  char l;
  char *unescaped;
  while (index < strlen (tmp_component))
    {
      l = *(tmp_component + index);

      if (l == '.' || l == '-' || l == '~')
        {
          g_string_append_printf (decoded_component, "\\%c", l);
          index++;
          embedded = TRUE;
          continue;
        }
      if (l != '%')
        {
          g_string_append_printf (decoded_component, "%c", l);
          index++;
          embedded = TRUE;
          continue;
        }

      get_code (code_a, tmp_component + index);

      if (strcmp (code_a, "%01") == 0)
        {
          if (index >= 3)
            get_code (code_b, tmp_component + index - 3);
          else
            code_b[0] = '0';
          if (strlen (tmp_component) >= index + 6)
            get_code (code_c, tmp_component + index + 3);
          else
            code_c[0] = '0';
          if ((index == 0 || index == strlen (tmp_component) - 3)
              || (!embedded && strcmp (code_b, "%01"))
              || (embedded && strcmp (code_c, "%01")))
            {
              g_string_append_printf (decoded_component, "%c", '?');
              index = index + 3;
              continue;
            }
          else
            {
              g_string_free (decoded_component, TRUE);
              g_free (tmp_component);
              return (NULL);
            }
        }

      if (strcmp (code_a, "%02") == 0)
        {
          if (index == 0 || index == strlen (tmp_component) - 3)
            {
              g_string_append_printf (decoded_component, "%c", '*');
              index = index + 3;
              continue;
            }
          else
            {
              g_string_free (decoded_component, TRUE);
              g_free (tmp_component);
              return (NULL);
            }
        }

      unescaped = g_uri_unescape_string (code_a, NULL);
      if (unescaped && strchr (escapes, *unescaped))
        {
          g_string_append_printf (decoded_component, "\\%s", unescaped);
          g_free (unescaped);
        }
      else if (unescaped)
        {
          g_string_append_printf (decoded_component, "%s", unescaped);
          g_free (unescaped);
        }
      else
        {
          g_string_free (decoded_component, TRUE);
          g_free (tmp_component);
          return (NULL);
        }
      index = index + 3;
      embedded = TRUE;
    }

  g_free (tmp_component);
  return (g_string_free (decoded_component, FALSE));
}

/**
 * @brief Unpack the sixth component of a URI CPE.
 *
 * @param[in]   component  The component to unpack.
 *
 * @param[out]  cpe        Pointer to the CPE struct where the unpacked and
 *                         decoded values of the component are stored.
 */
static void
unpack_sixth_uri_component (const char *component, cpe_struct_t *cpe)
{
  const char *start = component + 1;
  const char *end;

  char *edition, *sw_edition, *target_sw, *target_hw, *other;

  end = strchr (start, '~');
  if (start >= end || end == NULL)
    edition = strdup ("");
  else
    str_cpy (&edition, start, end - start);

  if (end != NULL)
    {
      start = end + 1;
      end = strchr (start, '~');
      if (start >= end || end == NULL)
        sw_edition = strdup ("");
      else
        str_cpy (&sw_edition, start, end - start);
    }
  else
    sw_edition = strdup ("");

  if (end != NULL)
    {
      start = end + 1;
      end = strchr (start, '~');
      if (start >= end || end == NULL)
        target_sw = strdup ("");
      else
        str_cpy (&target_sw, start, end - start);
    }
  else
    target_sw = strdup ("");

  if (end != NULL)
    {
      start = end + 1;
      end = strchr (start, '~');
      if (start >= end || end == NULL)
        target_hw = strdup ("");
      else
        str_cpy (&target_hw, start, end - start);
    }
  else
    target_hw = strdup ("");

  if (end != NULL)
    {
      start = end + 1;
      end = component + strlen (component);
      if (start >= end)
        other = strdup ("");
      else
        str_cpy (&other, start, end - start);
    }
  else
    other = strdup ("");

  cpe->edition = decode_uri_component (edition);
  g_free (edition);
  cpe->sw_edition = decode_uri_component (sw_edition);
  g_free (sw_edition);
  cpe->target_sw = decode_uri_component (target_sw);
  g_free (target_sw);
  cpe->target_hw = decode_uri_component (target_hw);
  g_free (target_hw);
  cpe->other = decode_uri_component (other);
  g_free (other);
}

/**
 * @brief Get the indexth component of a formatted string CPE.
 *
 * @param[in]   fs_cpe  The formatted string CPE.
 * @param[in]   index   The number of the component to get.
 *
 * @return  The indexth component of the formatted string CPE.
 */
static char *
get_fs_component (const char *fs_cpe, int index)
{
  char *component = NULL;
  char *c;
  char *component_start, *component_end;

  if (!fs_cpe)
    return NULL;

  if (*fs_cpe == '\0')
    return ((char *) g_strdup (""));

  c = (char *) fs_cpe;

  /* find start of component */
  if (index == 0)
    component_start = c;
  else
    {
      for (int i = 0; *c != '\0' && i < index; c++)
        {
          if (*c == ':' && c == fs_cpe)
            i++;
          else if (c > fs_cpe && *c == ':' && *(c - 1) != '\\')
            i++;
        }
      component_start = c;
    }

  /* find end of component */
  if (*component_start == '\0')
    component_end = component_start;
  else
    {
      for (c = component_start; *c != '\0' && *c != ':'; c++)
        ;
    }

  component_end = c;

  if (component_start >= component_end || component_end == NULL)
    component = (char *) g_strdup ("");
  else
    str_cpy (&component, component_start, component_end - component_start);

  return component;
}

/**
 * @brief Unbind a formatted string CPE component.
 *
 * @param[in]   component  The component to unbind.
 *
 * @return  The unbound component of the formatted string CPE.
 */
static char *
unbind_fs_component (char *component)
{
  if (strcmp (component, "*") == 0)
    return ((char *) g_strdup ("ANY"));
  if (strcmp (component, "-") == 0)
    return ((char *) g_strdup ("NA"));
  return (add_quoting (component));
}

/**
 * @brief Handle the quoting for an unbind formatted string CPE component.
 *
 * @param[in]   component  The component to add the quotings to.
 *
 * @return  The component of the formatted string CPE with all necessary
 *          quotes added.
 */
static char *
add_quoting (const char *component)
{
  GString *quoted_component;
  char *tmp_component;
  char *c;
  gboolean embedded;

  if (!component)
    return (NULL);

  quoted_component = g_string_new ("");
  tmp_component = (char *) g_strdup (component);
  embedded = FALSE;

  /* set all characters to lowercase */
  for (c = tmp_component; *c; c++)
    *c = tolower (*c);

  c = tmp_component;
  while (*c != '\0')
    {
      if (g_ascii_isalnum (*c) || *c == '_')
        {
          g_string_append_printf (quoted_component, "%c", *c);
          c++;
          embedded = TRUE;
          continue;
        }
      if (*c == '\\')
        {
          c++;
          if (*c != '\0')
            {
              g_string_append_printf (quoted_component, "\\%c", *c);
              embedded = TRUE;
              c++;
              continue;
            }
        }
      if (*c == '*')
        {
          if ((c == tmp_component)
              || (c == tmp_component + strlen (tmp_component - 1)))
            {
              g_string_append_printf (quoted_component, "%c", *c);
              c++;
              embedded = TRUE;
              continue;
            }
          else
            {
              g_free (tmp_component);
              return (NULL);
            }
        }
      if (*c == '?')
        {
          if ((c == tmp_component)
              || (c == tmp_component + strlen (tmp_component - 1))
              || (!embedded && (c > tmp_component) && (*(c - 1) == '?'))
              || (embedded && *(c + 1) == '?'))
            {
              g_string_append_printf (quoted_component, "%c", *c);
              c++;
              embedded = FALSE;
              continue;
            }
          else
            {
              g_free (tmp_component);
              return (NULL);
            }
        }
      g_string_append_printf (quoted_component, "\\%c", *c);
      c++;
      embedded = TRUE;
    }
  g_free (tmp_component);
  return (g_string_free (quoted_component, FALSE));
}

/**
 * @brief Bind a CPE component for a URI CPE.
 *
 * @param[in]   component  The component to bind.
 *
 * @return  The bound component for the URI CPE.
 */
static char *
bind_cpe_component_for_uri (const char *component)
{
  if (!component)
    return (g_strdup (""));
  if (strcmp (component, "") == 0)
    return (g_strdup (""));
  if (strcmp (component, "ANY") == 0)
    return (g_strdup (""));
  if (strcmp (component, "NA") == 0)
    return (g_strdup ("-"));
  return (transform_for_uri (component));
}

/**
 * @brief Transform a CPE component for a URI CPE.
 *
 * @param[in]   component  The component to transform.
 *
 * @return  The transformed component for the URI CPE.
 */
static char *
transform_for_uri (const char *component)
{
  GString *result;
  char *tmp_component;
  char *c;

  if (!component)
    return (g_strdup (""));
  if (strcmp (component, "") == 0)
    return (g_strdup (""));

  tmp_component = g_strdup (component);

  /* set all characters to lowercase */
  for (c = tmp_component; *c; c++)
    *c = tolower (*c);

  result = g_string_new ("");
  c = tmp_component;

  while (*c)
    {
      if ((g_ascii_isalnum (*c) || *c == '_') && *c != '-')
        {
          g_string_append_printf (result, "%c", *c);
          c++;
          continue;
        }
      if (*c == '\\')
        {
          c++;
          if (*c != '\0')
            {
              char to_escape[2];
              char *escaped;
              to_escape[0] = *c;
              to_escape[1] = '\0';
              escaped = g_uri_escape_string (to_escape, NULL, FALSE);
              g_string_append_printf (result, "%s", escaped);
              g_free (escaped);
              c++;
            }
          continue;
        }
      if (*c == '?')
        g_string_append_printf (result, "%s", "%01");
      if (*c == '*')
        g_string_append_printf (result, "%s", "%02");
      c++;
    }
  g_free (tmp_component);
  return (g_string_free (result, FALSE));
}

/**
 * @brief Pack the sixth component of a URI CPE.
 *
 * @param[in]   component  The CPE struct with the components to pack into the
 *                         sixth component of a URI CPE.
 *
 * @return  The packed component for the URI CPE.
 */
static char *
pack_sixth_uri_component (const cpe_struct_t *cpe)
{
  if ((cpe->sw_edition == NULL || strcmp (cpe->sw_edition, "") == 0)
      && (cpe->target_sw == NULL || strcmp (cpe->target_sw, "") == 0)
      && (cpe->target_hw == NULL || strcmp (cpe->target_hw, "") == 0)
      && (cpe->other == NULL || strcmp (cpe->other, "") == 0))
    {
      if (strcmp (cpe->edition, "ANY") == 0)
        return (g_strdup (""));
      if (strcmp (cpe->edition, "NA") == 0)
        return (g_strdup ("-"));
      return (g_strdup (cpe->edition));
    }

  char *edition = bind_cpe_component_for_uri (cpe->edition);
  char *sw_edition = bind_cpe_component_for_uri (cpe->sw_edition);
  char *target_sw = bind_cpe_component_for_uri (cpe->target_sw);
  char *target_hw = bind_cpe_component_for_uri (cpe->target_hw);
  char *other = bind_cpe_component_for_uri (cpe->other);
  GString *component;
  component = g_string_new ("");
  if (!((!sw_edition || strcmp (sw_edition, "") == 0)
        && (!target_sw || strcmp (target_sw, "") == 0)
        && (!target_hw || strcmp (target_hw, "") == 0)
        && (!other || strcmp (other, "") == 0)))
    g_string_append_printf (component, "~%s~%s~%s~%s~%s", edition, sw_edition,
                            target_sw, target_hw, other);
  else if (edition)
    g_string_append_printf (component, "%s", edition);

  if (edition)
    g_free (edition);
  if (sw_edition)
    g_free (sw_edition);
  if (target_sw)
    g_free (target_sw);
  if (target_hw)
    g_free (target_hw);
  if (other)
    g_free (other);
  return (g_string_free (component, FALSE));
}

/**
 * @brief Bind a CPE component for a formatted string CPE.
 *
 * @param[in]  component  The component to bind.
 *
 * @return  The bound component for the formatted string CPE.
 */
static char *
bind_cpe_component_for_fs (const char *component)
{
  if (!component)
    return (g_strdup ("*"));
  if (strcmp (component, "") == 0)
    return (g_strdup ("*"));
  if (strcmp (component, "ANY") == 0)
    return (g_strdup ("*"));
  if (strcmp (component, "NA") == 0)
    return (g_strdup ("-"));
  return (process_quoted_chars (component));
}

/**
 * @brief Process the quoted characters of a CPE component for
 *        a formatted string CPE.
 *
 * @param[in]  component  The component to process.
 *
 * @return  The processed component for the formatted string CPE.
 */
static char *
process_quoted_chars (const char *component)
{
  if (!component)
    return (g_strdup (""));
  if (strcmp (component, "") == 0)
    return (g_strdup (""));

  GString *fs_component;
  fs_component = g_string_new ("");
  char *c = (char *) component;
  char next_c;

  while (*c)
    {
      if (*c != '\\')
        {
          g_string_append_printf (fs_component, "%c", *c);
          c++;
        }
      else
        {
          next_c = *(c + 1);
          if (next_c == '.' || next_c == '-' || next_c == '_')
            {
              g_string_append_printf (fs_component, "%c", next_c);
              c += 2;
            }
          else if (next_c)
            {
              g_string_append_printf (fs_component, "\\%c", next_c);
              c += 2;
            }
        }
    }
  return (g_string_free (fs_component, FALSE));
}

/**
 * @brief Initialize a CPE struct.
 *
 * @param[in/out]  cpe  The pointer to the CPE to initialize.
 */
void
cpe_struct_init (cpe_struct_t *cpe)
{
  cpe->part = NULL;
  cpe->vendor = NULL;
  cpe->product = NULL;
  cpe->version = NULL;
  cpe->update = NULL;
  cpe->edition = NULL;
  cpe->sw_edition = NULL;
  cpe->target_sw = NULL;
  cpe->target_hw = NULL;
  cpe->other = NULL;
  cpe->language = NULL;

  /* to keep the compiler satisfied */
  cpe->part = cpe->part;
}

/**
 * @brief Free a CPE struct.
 *
 * @param[in/out]  cpe  The CPE to be freed.
 */
void
cpe_struct_free (cpe_struct_t *cpe)
{
  if (cpe->part)
    g_free (cpe->part);
  if (cpe->vendor)
    g_free (cpe->vendor);
  if (cpe->product)
    g_free (cpe->product);
  if (cpe->version)
    g_free (cpe->version);
  if (cpe->update)
    g_free (cpe->update);
  if (cpe->edition)
    g_free (cpe->edition);
  if (cpe->sw_edition)
    g_free (cpe->sw_edition);
  if (cpe->target_sw)
    g_free (cpe->target_sw);
  if (cpe->target_hw)
    g_free (cpe->target_hw);
  if (cpe->other)
    g_free (cpe->other);
  if (cpe->language)
    g_free (cpe->language);
}

/**
 * @brief Cut of trailing ':' signs.
 *
 * @param[in/out]  str  The string to be processed.
 */
static void
trim_pct (char *str)
{
  char *c;

  if (!str)
    return;
  c = str + strlen (str) - 1;
  while (c >= str)
    {
      if (*c == ':')
        {
          *c = '\0';
          c--;
        }
      else
        break;
    }
}

/**
 * @brief Get the percent code from the start of a string.
 *
 * @param[in]   str   The string to get the code from.
 * @param[out]  code  The percent code.
 */
static void
get_code (char *code, const char *str)
{
  code[0] = *str;
  code[1] = *(str + 1);
  code[2] = *(str + 2);
  code[3] = '\0';
}

/**
 * @brief Copy size characters of a string to an newly allocated new string.
 *
 * @param[in]   src   The string the first size characters are to be copied
 *                    from.
 * @param[in]   size  The number of characters to copy.
 *
 * @param[out]  dest  The copy of the first size characters of src.
 */
static void
str_cpy (char **dest, const char *src, int size)
{
  *dest = (char *) g_malloc (size + 1);
  memset (*dest, 0, size + 1);
  strncpy (*dest, src, size);
}

/**
 * @brief Returns if source is a match for target. That means
 *        that source is a superset of target.
 *
 * @param[in]  source  The cpe_struct that represents a set of CPEs.
 * @param[in]  target  The cpe_struct that represents a single CPE or
 *                     or a set of CPEs that is checked if it is a
 *                     subset of source meaning that it is matched by
 *                     source.
 *
 * @return  Returns if source is a match for target.
 */
gboolean
cpe_struct_match (cpe_struct_t source, cpe_struct_t target)
{
  enum set_relation relation;

  relation = compare_component (source.part, target.part);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.vendor, target.vendor);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.product, target.product);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.version, target.version);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.update, target.update);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.edition, target.edition);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.sw_edition, target.sw_edition);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.target_sw, target.target_sw);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.target_hw, target.target_hw);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.other, target.other);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);
  relation = compare_component (source.language, target.language);
  if (relation != SUPERSET && relation != EQUAL)
    return (FALSE);

  return (TRUE);
}

/**
 * @brief Returns if the component "source" is a match for the component
 *        "target". That means that source is a superset of target.
 *
 * @param[in]  source  The component of a cpe_struct.
 * @param[in]  target  The component of a cpe_struct that is checked if it
 *                     is a subset of source meaning that it is matched by
 *                     source.
 *
 * @return  Returns if source is a match for target.
 */
static enum set_relation
compare_component (const char *source, const char *target)
{
  enum set_relation result;
  char *source_cpy, *target_cpy;
  char *c;

  if (source)
    source_cpy = g_strdup (source);
  else
    source_cpy = g_strdup ("ANY");
  if (target)
    target_cpy = g_strdup (target);
  else
    target_cpy = g_strdup ("ANY");

  if (is_string (source_cpy))
    {
      /* set all characters to lowercase */
      for (c = source_cpy; *c; c++)
        *c = tolower (*c);
    }
  if (is_string (target_cpy))
    {
      /* set all characters to lowercase */
      for (c = target_cpy; *c; c++)
        *c = tolower (*c);
    }
  if (is_string (target_cpy) && has_wildcards (target_cpy))
    {
      g_free (source_cpy);
      g_free (target_cpy);
      return (UNDEFINED);
    }
  if (strcmp (source_cpy, target_cpy) == 0)
    {
      g_free (source_cpy);
      g_free (target_cpy);
      return (EQUAL);
    }
  if (strcmp (source_cpy, "ANY") == 0)
    {
      g_free (source_cpy);
      g_free (target_cpy);
      return (SUPERSET);
    }
  if (strcmp (target_cpy, "ANY") == 0)
    {
      g_free (source_cpy);
      g_free (target_cpy);
      return (SUBSET);
    }
  if (strcmp (target_cpy, "NA") == 0 || strcmp (source_cpy, "NA") == 0)
    {
      g_free (source_cpy);
      g_free (target_cpy);
      return (DISJOINT);
    }

  result = compare_strings (source_cpy, target_cpy);
  g_free (source_cpy);
  g_free (target_cpy);
  return (result);
}

/**
 * @brief Returns if the string of a component "source" is a match for the
 *        the string of a component "target". That means that source
 *        represents a superset of target.
 *
 * @param[in]  source  The string of a component of a cpe_struct.
 * @param[in]  target  The string of a component of a cpe_struct that is
 *                     checked if it represents a subset of source meaning
 *                     that it is matched by source.
 *
 * @return  Returns if source is a match for target.
 */
static enum set_relation
compare_strings (const char *source, const char *target)
{
  int start = 0;
  int end = strlen (source);
  int begins = 0;
  int ends = 0;

  char *sub_source;

  if (*source == '*')
    {
      start = 1;
      begins = -1;
    }
  else
    {
      while (start < (int) strlen (source) && *(source + start) == '?')
        {
          start++;
          begins++;
        }
    }
  if (*(source + end - 1) == '*' && is_even_wildcards (source, end - 1))
    {
      end--;
      ends = -1;
    }
  else
    {
      while (end > 0 && *(source + end - 1) == '?'
             && is_even_wildcards (source, end - 1))
        {
          end--;
          ends++;
        }
    }

  str_cpy (&sub_source, source + start, end - start);
  int index = -1;
  int escapes = 0;
  int leftover = strlen (target);

  while (leftover > 0)
    {
      index = index_of (target, sub_source, index + 1);
      if (index == -1)
        break;
      escapes = count_escapes (target, 0, index);
      if (index > 0 && begins != -1 && begins < (index - escapes))
        break;
      escapes = count_escapes (target, index + 1, strlen (target));
      leftover = strlen (target) - index - escapes - strlen (sub_source);
      if (leftover > 0 && (ends != -1 && leftover > ends))
        continue;
      g_free (sub_source);
      return SUPERSET;
    }
  g_free (sub_source);
  return DISJOINT;
}

/**
 * @brief Counts the number of unescaped escape signs ("\") in a specified
 *        part of a string.
 *
 * @param[in]  str    The string to be examined.
 * @param[in]  start  The start position in the string where the examination
 *                    begins.
 * @param[in]  end    The end position in the string where the examination
 *                    ends.
 *
 * @return  Returns the number of unescaped escape signs in the specified
 *          part of the string.
 */
static int
count_escapes (const char *str, int start, int end)
{
  int result = 0;
  gboolean active = FALSE;

  for (int i = 0; i < end && *(str + i) != '\0'; i++)
    {
      active = (!active && *(str + i) == '\\');
      if (active && i >= start)
        result++;
    }
  return (result);
}

/**
 * @brief Returns true if an even number of escape (backslash) characters
 *        precede the character at the index "index" in string "str".
 *
 * @param[in]  str    The string to be examined.
 * @param[in]  index  The index where the examination starts.
 *
 * @return  Returns if an even number of escape characters precede the
 *          character at index "index".
 */
static gboolean
is_even_wildcards (const char *str, int index)
{
  int result = 0;

  while (index > 0 && *(str + index - 1) == '\\')
    {
      index--;
      result++;
    }
  return ((result % 2) == 0);
}

/**
 * @brief Returns if a given string contains wildcards ("*" or "?").
 *
 * @param[in]  str  The string to be examined.
 *
 * @return  Returns TRUE if the string contains wildcards. FALSE otherwise.
 */
static gboolean
has_wildcards (const char *str)
{
  char *c = (char *) str;
  gboolean active = FALSE;

  while (*c != '\0')
    {
      if (!active && (*c == '?' || *c == '*'))
        return TRUE;

      if (!active && *c == '\\')
        active = TRUE;
      else
        active = FALSE;

      c++;
    }
  return FALSE;
}

/**
 * @brief Searches the string "str" for the first occurrence of the string
 *        "sub_str", starting at the offset "offset" in "str".
 *
 * @param[in]  str      The string to be examined.
 * @param[in]  sub_str  The string to be searched for in "str".
 * @param[in]  offset   The offset where to start the search in "str".
 *
 * @return  Returns the index where the string "sub_str" starts in "str", if
 *          the string "sub_str" was found, -1 otherwise.
 */
static int
index_of (const char *str, const char *sub_str, int offset)
{
  char *start;
  char *begin_substr;

  if (offset > (int) strlen (str))
    return (-1);

  start = (char *) str + offset;
  begin_substr = strstr (start, sub_str);
  if (begin_substr == NULL)
    return (-1);
  return (begin_substr - str);
}

/**
 * @brief Returns if a string is an ordinary string and does not represent
 *        one of the logical values "ANY" or "NA".
 *
 * @param[in]  str  The string to be examined.
 *
 * @return  Returns TRUE if the string "str" does not represent one of the
 *          logical values "ANY" or "NA". Returns FALSE otherwise.
 */
static gboolean
is_string (const char *str)
{
  if (!str)
    return TRUE;

  return (strcmp (str, "ANY") && strcmp (str, "NA"));
}
