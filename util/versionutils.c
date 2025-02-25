/* SPDX-FileCopyrightText: 2009-2024 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Functions to handle version numbers / version strings.
 *
 * Up to now this library provides a function to compare two version numbers /
 * two version strings to decide which version is the newer one.
 */

#include "versionutils.h"

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

static gchar *
prepare_version_string (const char *);

static int
get_release_state (const char *, int);

static char *
get_part (const char *, int);

static gboolean
is_text (const char *);

static char *
str_cpy (char *, int);

/**
 * @brief Compare two version strings representing a software version
 *        to decide which version is newer.
 *
 * @param[in]  version1  The first version string to compare.
 * @param[in]  version2  The second version string to compare.
 *
 * @return  Returns a value > 0 if version1 is newer than version2.
 *          Returns 0 if version1 is the same than version2.
 *          Returns a value between -1 and -4 if version2 is newer
 *          than version1.
 *          Returns -5 if the result is undefined.
 */
int
cmp_versions (const char *version1, const char *version2)
{
  char *ver1, *ver2;
  char *part1, *part2;
  int index1 = 0, index2 = 0;
  int release_state1 = 0, release_state2 = 0;
  int rs1, rs2;

  ver1 = prepare_version_string (version1);
  ver2 = prepare_version_string (version2);

  if (ver1 == NULL || ver2 == NULL)
    {
      g_free (ver1);
      g_free (ver2);
      return (-5);
    }
  if (strcmp (ver1, ver2) == 0)
    {
      g_free (ver1);
      g_free (ver2);
      return (0);
    }

  release_state1 = get_release_state (ver1, index1);
  if (release_state1)
    index1++;
  release_state2 = get_release_state (ver2, index2);
  if (release_state2)
    index2++;

  part1 = get_part (ver1, index1);
  part2 = get_part (ver2, index2);
  while (part1 && part2)
    {
      if (strcmp (part1, part2) == 0)
        {
          index1++;
          index2++;
          g_free (part1);
          g_free (part2);
          part1 = get_part (ver1, index1);
          part2 = get_part (ver2, index2);
          continue;
        }
      else
        break;
    }

  if (part1 == NULL && part2 == NULL)
    return (release_state2 - release_state1);

  if (is_text (part1) || is_text (part2))
    {
      if (part1)
        g_free (part1);
      if (part2)
        g_free (part2);
      return (-5); // undefined
    }

  rs1 = get_release_state (ver1, index1);
  rs2 = get_release_state (ver2, index2);

  if ((rs1 && release_state1) || (rs2 && release_state2))
    return (-5); // undefined

  if (part1 == NULL)
    {
      g_free (part2);
      if (rs2)
        return (rs2 - release_state1);
      else
        return (-1);
    }

  if (part2 == NULL)
    {
      g_free (part1);
      if (rs1)
        return (release_state2 - rs1);
      else
        return (1);
    }

  int ret = -5;

  if (rs1 && rs2)
    ret = rs2 - rs1;

  if (rs1)
    ret = -1;

  if (rs2)
    ret = 1;

  if (!rs1 && !rs2 && atoi (part1) < atoi (part2))
    ret = -1;

  if (!rs1 && !rs2 && atoi (part1) == atoi (part2))
    ret = 0;

  if (!rs1 && !rs2 && atoi (part1) > atoi (part2))
    ret = 1;

  g_free (part1);
  g_free (part2);
  g_free (ver1);
  g_free (ver2);
  return (ret);
}

/**
 * @brief Prepare the version string for comparison.
 *
 * @param[in]  version  The version string to generate the prepared
 *                      version string from.
 *
 * @return  Returns a prepared copy of the version string version.
 */
static gchar *
prepare_version_string (const char *version)
{
  char prep_version[2048];
  char *ver;
  int index_v, index_pv;
  gboolean is_digit;

  if (!version)
    return (NULL);

  if (strlen (version) > 1024)
    return (NULL);

  ver = g_strdup (version);

  /* set all characters to lowercase */
  char *c = ver;
  for (; *c; c++)
    *c = tolower (*c);

  index_v = index_pv = 0;

  is_digit = g_ascii_isdigit (ver[0]);

  while (index_v < (int) strlen (ver) && index_pv < 2047)
    {
      if (ver[index_v] == '\\')
        {
          index_v++;
          continue;
        }

      if (ver[index_v] == '_' || ver[index_v] == '-' || ver[index_v] == '+'
          || ver[index_v] == ':' || ver[index_v] == '.')
        {
          if (index_pv > 0 && prep_version[index_pv - 1] != '.')
            {
              prep_version[index_pv] = '.';
              index_pv++;
            }
          index_v++;
          continue;
        }

      if (is_digit != g_ascii_isdigit (ver[index_v]))
        {
          is_digit = !is_digit;
          if (index_pv > 0 && prep_version[index_pv - 1] != '.')
            {
              prep_version[index_pv] = '.';
              index_pv++;
            }
        }

      if (ver[index_v] == 'r')
        {
          if (strstr (ver + index_v, "releasecandidate") == ver + index_v)
            {
              prep_version[index_pv] = 'r';
              prep_version[index_pv + 1] = 'c';
              index_pv += 2;
              index_v += 16;
              continue;
            }
          if ((strstr (ver + index_v, "release-candidate") == ver + index_v)
              || (strstr (ver + index_v, "release_candidate") == ver + index_v))
            {
              prep_version[index_pv] = 'r';
              prep_version[index_pv + 1] = 'c';
              index_pv += 2;
              index_v += 17;
              continue;
            }
        }

      prep_version[index_pv] = ver[index_v];
      index_v++;
      index_pv++;
    }

  prep_version[index_pv] = '\0';
  g_free (ver);
  return (g_strdup (prep_version));
}

/**
 * @brief Gets the release state of a specified part of the version string
 *        if any.
 *
 * @param[in]  version  The version string to get the release state from.
 * @param[in]  index    The part of the version string to check.
 *
 * @return  Returns 0 if there is no release state, returns 4 if the release
 *          state is "development" (dev), returns 3 if the state is "alpha",
 *          2 if the state is beta and 1 if the state is release candidate (rc).
 */
static int
get_release_state (const char *version, int index)
{
  char *part;
  int rel_stat = 0;

  part = get_part (version, index);

  if (part == NULL)
    return (0);

  if (strcmp (part, "dev") == 0 || strcmp (part, "development") == 0)
    rel_stat = 4;
  if (strcmp (part, "alpha") == 0)
    rel_stat = 3;
  if (strcmp (part, "beta") == 0)
    rel_stat = 2;
  if (strcmp (part, "rc") == 0)
    rel_stat = 1;

  g_free (part);
  return (rel_stat);
}

/**
 * @brief Gets the part of the version string that is specified by index.
 *
 * @param[in]  version  The version string to get the part from.
 * @param[in]  index    The part of the version string to return.
 *
 * @return  Returns a copy of the specified part of the version string.
 */
static char *
get_part (const char *version, int index)
{
  int dot_count = 0;
  int begin, end;

  for (begin = 0; begin < (int) strlen (version) && dot_count < index; begin++)
    {
      if (version[begin] == '.')
        dot_count++;
    }

  if (begin == (int) strlen (version))
    return (NULL);

  for (end = begin + 1; end < (int) strlen (version) && version[end] != '.';
       end++)
    ;

  return (str_cpy ((char *) (version + begin), end - begin));
}

/**
 * @brief Checks if a given part of the version string is plain text.
 *
 * @param[in]  part  The part of the version string to check.
 *
 * @return  Returns TRUE if part contains only plain text, FALSE otherwise.
 */
static gboolean
is_text (const char *part)
{
  if (!part)
    return (FALSE);
  if (strcmp (part, "dev") == 0 || strcmp (part, "alpha") == 0
      || strcmp (part, "beta") == 0 || strcmp (part, "rc") == 0)
    return (FALSE);
  if (g_ascii_isdigit (*part))
    return (FALSE);
  return (TRUE);
}

/**
 * @brief Copy size characters of a string to an newly allocated new string.
 *
 * @param[in]   src   The string the first size characters are to be copied
 *                    from.
 * @param[in]   size  The number of characters to copy.
 *
 * @return  The copy of the first size characters of src as a new string.
 */
static char *
str_cpy (char *source, int size)
{
  char *result;
  result = (char *) g_malloc (size + 1);
  memset (result, 0, size + 1);
  strncpy (result, source, size);
  return (result);
}
