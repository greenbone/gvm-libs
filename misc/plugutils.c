/* OpenVAS
 * $Id$
 * Description: Plugin-specific stuff.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2003 Renaud Deraison
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#include <glib.h>

#include "arglists.h"
#include "kb.h"
#include "network.h"
#include "plugutils.h"
#include "internal_com.h" /* for INTERNAL_COMM_MSG_TYPE_KB */
#include "system.h"
#include "scanners_utils.h"
#include "openvas_logging.h"

#include "../base/nvticache.h" /* for nvticache_get_by_oid() */

/* Used to allow debugging for openvas-nasl */
int global_nasl_debug = 0;

/**
 * @brief Escapes \\n and \\r and \\ in \<in\> properly. The
 * @brief resulting string is copied and returned.
 *
 * @param in String in which to escape \\n, \\r and \\.
 *
 * @return Copy of in with \\n, \\r and \\ escaped, NULL if @ref in is NULL.
 *
 * @see To undo, call rmslashes.
 */
char *
addslashes (char *in)
{
  char *ret;
  char *out;

  if (in == NULL)
    return NULL;

  out = malloc (strlen (in) * 2 + 1);
  bzero (out, strlen (in) * 2 + 1);
  ret = out;
  while (in[0])
    {
      if (in[0] == '\\')
        {
          out[0] = '\\';
          out++;
          out[0] = '\\';
          out++;
        }

      else if (in[0] == '\n')
        {
          out[0] = '\\';
          out++;
          out[0] = 'n';
          out++;
        }
      else if (in[0] == '\r')
        {
          out[0] = '\\';
          out++;
          out[0] = 'r';
          out++;
        }
      else
        {
          out[0] = in[0];
          out++;
        }
      in++;
    }
  return realloc (ret, strlen (ret) + 1);
}

/**
 * @brief Replaces escape codes (\\n, \\r) by the real value.
 *
 * The resulting string is stored in another buffer.
 *
 * @see (slashes could have been added with addslashes)
 */
char *
rmslashes (char *in)
{
  char *out = malloc (strlen (in) + 1);
  char *ret = out;
  bzero (out, strlen (in) + 1);
  while (in[0])
    {
      if (in[0] == '\\')
        {
          switch (in[1])
            {
            case 'r':
              out[0] = '\r';
              in++;
              break;
            case 'n':
              out[0] = '\n';
              in++;
              break;
            case '\\':
              out[0] = '\\';
              in++;
              break;
            default:
              log_legacy_write ("Unknown escape sequence '\\%c'", in[1]);
            }
        }
      else
        out[0] = in[0];
      in++;
      out++;
    }
  return realloc (ret, strlen (ret) + 1);
}

void
plug_set_xref (struct arglist *desc, char *name, char *value)
{
  nvti_t *n = arg_get_value (desc, "NVTI");
  char *new;

  if (nvti_xref (n))
    new = g_strconcat (nvti_xref (n), ", ", name, ":", value, NULL);
  else
    new = g_strconcat (name, ":", value, NULL);

  nvti_set_xref (n, new);
  g_free (new);
}

void
plug_set_tag (struct arglist *desc, char *name, char *value)
{
  nvti_t *n = arg_get_value (desc, "NVTI");
  char *new;

  if (nvti_tag (n))
    new = g_strconcat (nvti_tag (n), "|", name, "=", value, NULL);
  else
    new = g_strconcat (name, "=", value, NULL);

  nvti_set_tag (n, new);
  g_free (new);
}

void
plug_set_dep (struct arglist *desc, const char *depname)
{
  nvti_t *n = arg_get_value (desc, "NVTI");
  gchar * old = nvti_dependencies (n);
  gchar * new;

  if (!depname) return;

  if (old)
    {
      new = g_strdup_printf ("%s, %s", old, depname);
      nvti_set_dependencies (n, new);
      g_free (new);
    }
  else
    nvti_set_dependencies (n, depname);
}

void
plug_set_launch (struct arglist *desc, int launch)
{
  if (arg_set_value
      (desc, "ENABLED", sizeof (gpointer), GSIZE_TO_POINTER (launch)))
    {
      arg_add_value (desc, "ENABLED", ARG_INT, sizeof (gpointer),
                     GSIZE_TO_POINTER (launch));
    }
}


int
plug_get_launch (struct arglist *desc)
{
  return (GPOINTER_TO_SIZE (arg_get_value (desc, "ENABLED")));
}

void
_add_plugin_preference (struct arglist *prefs, const char *p_name,
                        const char *name, const char *type, const char *defaul)
{
  char *pref;
  char *cname;
  int len;

  cname = estrdup (name);
  len = strlen (cname);
  // Terminate string before last trailing space
  while (cname[len - 1] == ' ')
    {
      cname[len - 1] = '\0';
      len--;
    }
  if (!prefs || !p_name)
    {
      efree (&cname);
      return;
    }


  pref = emalloc (strlen (p_name) + 10 + strlen (type) + strlen (cname));
  // RATS: ignore
  snprintf (pref, strlen (p_name) + 10 + strlen (type) + strlen (cname),
            "%s[%s]:%s", p_name, type, cname);
  if (arg_get_value (prefs, pref) == NULL)
    arg_add_value (prefs, pref, ARG_STRING, strlen (defaul), estrdup (defaul));

  efree (&cname);
  efree (&pref);
}

/**
 * @brief Returns a (plugin) arglist assembled from the nvti.
 *
 * @param nvti NVT Information to be used for the creation.
 *
 * @param prefs Plugin preference arglist that is added to
 *              new arglist and where all preferences of the NVTI
 *              are copied to as single entries.
 *
 * @return Pointer to plugin as arglist or NULL.
 */
struct arglist *
plug_create_from_nvti_and_prefs (nvti_t * nvti, struct arglist *prefs)
{
  struct arglist *ret;
  int i;

  if (!nvti)
    return NULL;

  ret = emalloc (sizeof (struct arglist));

  arg_add_value (ret, "OID", ARG_STRING, strlen (nvti_oid (nvti)),
                 g_strdup (nvti_oid (nvti)));
  arg_add_value (ret, "preferences", ARG_ARGLIST, -1, prefs);

  for (i = 0; i < nvti_pref_len (nvti); i++)
    {
      nvtpref_t *np = nvti_pref (nvti, i);
      _add_plugin_preference (prefs, nvti_name (nvti), nvtpref_name (np),
                              nvtpref_type (np), nvtpref_default (np));
    }

  return ret;
}

void
host_add_port_proto (struct arglist *args, int portnum, int state, char *proto)
{
  char port_s[255];
  snprintf (port_s, sizeof (port_s), "Ports/%s/%d", proto, portnum);    /* RATS: ignore */
  plug_set_key (args, port_s, ARG_INT, (void *) 1);
}

/**
 * @brief Report state of preferences "unscanned_closed".
 *
 * @return 0 if pref is "yes", 1 otherwise.
 */
static int
unscanned_ports_as_closed (struct arglist *prefs, port_protocol_t ptype)
{
  char *unscanned;

  if (ptype == PORT_PROTOCOL_UDP)
    unscanned = arg_get_value (prefs, "unscanned_closed_udp");
  else
    unscanned = arg_get_value (prefs, "unscanned_closed");

  if (unscanned && !strcmp (unscanned, "yes"))
    return 0;
  else
    return 1;
}

/**
 * @param proto Protocol (udp/tcp). If NULL, "tcp" will be used.
 */
int
kb_get_port_state_proto (kb_t kb, struct arglist *prefs, int portnum,
                         char *proto)
{
  char port_s[255], *kbstr;
  char *prange = (char *) arg_get_value (prefs, "port_range");
  port_protocol_t port_type;
  array_t *port_ranges;

  if (proto && !strcmp (proto, "udp"))
    {
      port_type = PORT_PROTOCOL_UDP;
      kbstr = "Host/udp_scanned";
    }
  else
    {
      port_type = PORT_PROTOCOL_TCP;
      kbstr = "Host/scanned";
    }

  /* Check that we actually scanned the port */
  if (kb_item_get_int (kb, kbstr) <= 0)
    return unscanned_ports_as_closed (prefs, port_type);

  port_ranges = port_range_ranges (prange);
  if (!port_in_port_ranges (portnum, port_type, port_ranges))
    {
      array_free (port_ranges);
      return unscanned_ports_as_closed (prefs, port_type);
    }
  array_free (port_ranges);

  /* Ok, we scanned it. What is its state ? */
  snprintf (port_s, sizeof (port_s), "Ports/%s/%d", proto, portnum);
  return kb_item_get_int (kb, port_s) > 0;
}

int
host_get_port_state_proto (struct arglist *plugdata, int portnum, char *proto)
{
  kb_t kb = plug_get_kb (plugdata);
  struct arglist *prefs = arg_get_value (plugdata, "preferences");

  return kb_get_port_state_proto (kb, prefs, portnum, proto);
}

int
host_get_port_state (struct arglist *plugdata, int portnum)
{
  return (host_get_port_state_proto (plugdata, portnum, "tcp"));
}

int
host_get_port_state_udp (struct arglist *plugdata, int portnum)
{
  return (host_get_port_state_proto (plugdata, portnum, "udp"));
}


const char *
plug_get_hostname (struct arglist *desc)
{
  struct arglist *hinfos = arg_get_value (desc, "HOSTNAME");
  if (hinfos)
    return ((char *) arg_get_value (hinfos, "NAME"));
  else
    return (NULL);
}

const char *
plug_get_host_fqdn (struct arglist *desc)
{
  struct arglist *hinfos = arg_get_value (desc, "HOSTNAME");
  if (hinfos)
    {
      int type;
      char *vhosts = plug_get_key (desc, "hostinfos/vhosts", &type);
      if (vhosts)
        return vhosts;
      else
        return ((char *) arg_get_value (hinfos, "FQDN"));
    }
  else
    return (NULL);
}


struct in6_addr *
plug_get_host_ip (struct arglist *desc)
{
  struct arglist *hinfos = arg_get_value (desc, "HOSTNAME");
  if (hinfos)
    return ((struct in6_addr *) arg_get_value (hinfos, "IP"));
  else
    return NULL;
}


/**
 * @brief Sets a Success kb- entry for the plugin described with parameter desc.
 *
 * @param desc Plugin-arglist.
 */
static void
mark_successful_plugin (struct arglist *desc)
{
  char data[512];

  bzero (data, sizeof (data));
  snprintf (data, sizeof (data), "Success/%s",
            (char *)arg_get_value (desc, "OID"));    /* RATS: ignore */
  plug_set_key (desc, data, ARG_INT, (void *) 1);
}

static void
mark_post (struct arglist *desc, const char *action, const char *content)
{
  char entry_name[255];
  char *ccontent = estrdup (content);

  if (strlen (action) > (sizeof (entry_name) - 20))
    return;

  snprintf (entry_name, sizeof (entry_name), "SentData/%s/%s",
            (char *)arg_get_value (desc, "OID"), action);    /* RATS: ignore */
  plug_set_key (desc, entry_name, ARG_STRING, ccontent);
}

/**
 * @brief Post a security message (e.g. LOG, NOTE, WARNING ...).
 *
 * @param desc  The arglist where to get the nvtichache from and some
 *              other settings and it is used to send the messages
 * @param port  Port number related to the issue.
 * @param proto Protocol related to the issue (tcp or udp).
 * @param action The actual result text
 * @param what   The type, like "LOG".
 */
void
proto_post_wrapped (struct arglist *desc, int port, const char *proto,
                    const char *action, const char *what)
{
  char *buffer;
  int soc;
  int len;
  char *prepend_tags;
  char *append_tags;
  GString *action_str;
  gchar *data;
  gsize length;
  nvti_t * nvti = nvticache_get_by_oid (arg_get_value (arg_get_value (desc,
    "preferences"), "nvticache"), arg_get_value (desc, "OID"));
  gchar **nvti_tags = NULL;

  /* Should not happen, just to avoid trouble stop here if no NVTI found */
  if (nvti == NULL)
    return;

  if (action == NULL)
    action_str = g_string_new ("");
  else
    {
      action_str = g_string_new (action);
      g_string_append (action_str, "\n");
    }

  prepend_tags = get_preference (desc, "result_prepend_tags");
  append_tags = get_preference (desc, "result_append_tags");

  if (prepend_tags || append_tags)
    {
      nvti_tags = g_strsplit (nvti_tag (nvti), "|", 0);
    }

  /* This is convenience functionality in preparation for the breaking up of the
   * NVT description block and adding proper handling of refined meta
   * information all over the OpenVAS Framework.
   */
  if (nvti_tags != NULL)
    {
      if (prepend_tags != NULL)
        {
          gchar **tags = g_strsplit (prepend_tags, ",", 0);
          int i = 0;
          gchar *tag_prefix;
          gchar *tag_value;
          while (tags[i] != NULL)
            {
              int j = 0;
              tag_value = NULL;
              tag_prefix = g_strconcat (tags[i], "=", NULL);
              while (nvti_tags[j] != NULL && tag_value == NULL)
                {
                  if (g_str_has_prefix (nvti_tags[j], tag_prefix))
                    {
                      tag_value = g_strstr_len (nvti_tags[j], -1, "=");
                    }
                  j++;
                }
              g_free (tag_prefix);

              if (tag_value != NULL)
                {
                  tag_value = tag_value + 1;
                  gchar *tag_line = g_strdup_printf ("%s:\n%s\n\n", tags[i],
                                                     tag_value);
                  g_string_prepend (action_str, tag_line);

                  g_free (tag_line);
                }
              i++;
            }
          g_strfreev (tags);
        }

      if (append_tags != NULL)
        {
          gchar **tags = g_strsplit (append_tags, ",", 0);
          int i = 0;
          gchar *tag_prefix;
          gchar *tag_value;

          while (tags[i] != NULL)
            {
              int j = 0;
              tag_value = NULL;
              tag_prefix = g_strconcat (tags[i], "=", NULL);
              while (nvti_tags[j] != NULL && tag_value == NULL)
                {
                  if (g_str_has_prefix (nvti_tags[j], tag_prefix))
                    {
                      tag_value = g_strstr_len (nvti_tags[j], -1, "=");
                    }
                  j++;
                }
              g_free (tag_prefix);

              if (tag_value != NULL)
                {
                  tag_value = tag_value + 1;
                  gchar *tag_line = g_strdup_printf ("%s:\n%s\n\n", tags[i],
                                                     tag_value);
                  g_string_append (action_str, tag_line);

                  g_free (tag_line);
                }
              i++;
            }
          g_strfreev (tags);
        }
    }

  len = action_str->len;
  buffer = emalloc (1024 + len);
  char idbuffer[105];
  if (nvti_oid (nvti) == NULL)
    {
      *idbuffer = '\0';
    }
  else
    {
      char *oid = nvti_oid (nvti);
      snprintf (idbuffer, sizeof (idbuffer), "<|> %s ", oid);   /* RATS: ignore */
    }
  if (port > 0)
    {
      snprintf (buffer, 1024 + len,
                "SERVER <|> %s <|> %s <|> %d/%s <|> %s %s<|> SERVER\n",
                what, plug_get_hostname (desc), port, proto,
                action_str->str, idbuffer);
    }
  else
    snprintf (buffer, 1024 + len,
              "SERVER <|> %s <|> %s <|> general/%s <|> %s %s<|> SERVER\n", what,
              plug_get_hostname (desc), proto, action_str->str,
              idbuffer);

  mark_post (desc, what, action);
  soc = GPOINTER_TO_SIZE (arg_get_value (desc, "SOCKET"));
  /* Convert to UTF-8 before sending to Manager. */
  data = g_convert (buffer, -1, "UTF-8", "ISO_8859-1", NULL, &length, NULL);
  internal_send (soc, data, INTERNAL_COMM_MSG_TYPE_DATA);
  g_free (data);

  nvti_free (nvti);

  /* Mark in the KB that the plugin was successful */
  mark_successful_plugin (desc);
  efree (&buffer);
  g_string_free (action_str, TRUE);
}

void
proto_post_alarm (struct arglist *desc, int port, const char *proto,
                  const char *action)
{
  proto_post_wrapped (desc, port, proto, action, "ALARM");
}

void
post_alarm (struct arglist *desc, int port, const char *action)
{
  proto_post_alarm (desc, port, "tcp", action);
}


/**
 * @brief Post a log message
 */
void
proto_post_log (struct arglist *desc, int port, const char *proto,
                const char *action)
{
  proto_post_wrapped (desc, port, proto, action, "LOG");
}

/**
 * @brief Post a log message about a tcp port.
 */
void
post_log (struct arglist *desc, int port, const char *action)
{
  proto_post_log (desc, port, "tcp", action);
}

void
proto_post_error (struct arglist *desc, int port, const char *proto,
                  const char *action)
{
  proto_post_wrapped (desc, port, proto, action, "ERRMSG");
}


void
post_error (struct arglist *desc, int port, const char *action)
{
  proto_post_error (desc, port, "tcp", action);
}

char *
get_preference (struct arglist *desc, const char *name)
{
  struct arglist *prefs;
  prefs = arg_get_value (desc, "preferences");
  if (!prefs)
    return (NULL);
  return ((char *) arg_get_value (prefs, name));
}

void
add_plugin_preference (struct arglist *desc, const char *name, const char *type,
                       const char *defaul)
{
  nvti_t *n = arg_get_value (desc, "NVTI");
  nvtpref_t *np = nvtpref_new ((gchar *)name, (gchar *)type, (gchar *)defaul);

  nvti_add_pref (n, np);
}


char *
get_plugin_preference (struct arglist *desc, const char *name)
{
  int len;
  struct arglist *prefs;
  char *plug_name, *cname;

  prefs = arg_get_value (desc, "preferences");
  if (!prefs)
    return NULL;

  nvti_t * nvti = nvticache_get_by_oid (arg_get_value (prefs, "nvticache"),
                                        arg_get_value (desc, "OID"));
  plug_name = nvti_name (nvti);
  cname = estrdup (name);

  len = strlen (cname);

  while (cname[len - 1] == ' ')
    {
      cname[len - 1] = '\0';
      len--;
    }

  while (prefs->next)
    {
      char *a = NULL, *b = NULL;
      int c = 0;
      char *t = prefs->name;

      a = strchr (t, '[');
      if (a)
        b = strchr (t, ']');
      if (b)
        c = (b[1] == ':');

      if (c)
        {
          b += 2 * sizeof (char);
          if (!strcmp (cname, b))
            {
              int old = a[0];
              a[0] = 0;
              if (!strcmp (t, plug_name))
                {
                  a[0] = old;
                  efree (&cname);
                  nvti_free (nvti);
                  return (prefs->value);
                }
              a[0] = old;
            }
        }
      prefs = prefs->next;
    }
  efree (&cname);
  nvti_free (nvti);
  return (NULL);
}

/**
 * @brief Get the file name of a plugins preference that is of type "file".
 *
 * As files sent to the server (e.g. as plugin preference) are stored at
 * pseudo-random locations with different names, the "real" file name has to be
 * looked up in a hashtable.
 *
 * @return Filename on disc for \ref filename, NULL if not found or setup
 *         broken.
 */
const char *
get_plugin_preference_fname (struct arglist *desc, const char *filename)
{
  const char *content;
  long contentsize = 0;
  gint tmpfile;
  gchar *tmpfilename;
  GError *error = NULL;

  content = get_plugin_preference_file_content (desc, filename);
  if (content == NULL)
    {
      return NULL;
    }
  contentsize = get_plugin_preference_file_size (desc, filename);
  if (contentsize <= 0)
    return NULL;

  tmpfile =
    g_file_open_tmp ("openvassd-file-upload.XXXXXX", &tmpfilename, &error);
  if (tmpfile == -1)
    {
      log_legacy_write ("get_plugin_preference_fname: Could not open temporary"
                        " file for %s: %s", filename, error->message);
      g_error_free (error);
      return NULL;
    }
  close (tmpfile);

  if (!g_file_set_contents (tmpfilename, content, contentsize, &error))
    {
      log_legacy_write ("get_plugin_preference_fname: could set contents of"
                        " temporary file for %s: %s", filename, error->message);
      g_error_free (error);
      return NULL;
    }

  return tmpfilename;
}


/**
 * @brief Get the file contents of a plugins preference that is of type "file".
 *
 * As files sent to the scanner (e.g. as plugin preference) are stored in a hash
 * table with an identifier supplied by the client as the key, the contents have
 * to be looked up here.
 *
 * @param identifier Identifier that was supplied by the client when the file
 *                   was uploaded.
 *
 * @return Contents of the file identified by \ref identifier, NULL if not found or setup
 *         broken.
 */
char *
get_plugin_preference_file_content (struct arglist *desc,
                                    const char *identifier)
{
  struct arglist *globals = arg_get_value (desc, "globals");
  GHashTable *trans;

  if (!globals)
    return NULL;

  trans = arg_get_value (globals, "files_translation");
  if (!trans)
    return NULL;

  return g_hash_table_lookup (trans, identifier);
}


/**
 * @brief Get the file size of a plugins preference that is of type "file".
 *
 * Files sent to the scanner (e.g. as plugin preference) are stored in a hash
 * table with an identifier supplied by the client as the key. The size of the
 * file is stored in a separate hash table with the same identifier as key,
 * which can be looked up here.
 *
 * @param identifier Identifier that was supplied by the client when the file
 *                   was uploaded.
 *
 * @return Size of the file identified by \ref identifier, -1 if not found or
 *         setup broken.
 */
const long
get_plugin_preference_file_size (struct arglist *desc, const char *identifier)
{
  struct arglist *globals = arg_get_value (desc, "globals");
  GHashTable *trans;
  gchar *filesize_str;

  if (!globals)
    return -1;

  trans = arg_get_value (globals, "files_size_translation");
  if (!trans)
    return -1;

  filesize_str = g_hash_table_lookup (trans, identifier);
  if (filesize_str == NULL)
    return -1;

  return atol (filesize_str);
}


void *
plug_get_fresh_key (struct arglist *args, char *name, int *type)
{
  struct arglist *globals = arg_get_value (args, "globals");
  int soc = GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));
  int e;
  char *buf = NULL;
  int bufsz = 0;
  int msg;

  if (name == NULL || type == NULL)
    return NULL;
  *type = -1;

  e =
    internal_send (soc, name, INTERNAL_COMM_MSG_TYPE_KB | INTERNAL_COMM_KB_GET);
  if (e < 0)
    {
      log_legacy_write ("[%d] plug_get_fresh_key:internal_send(%d, %s): %s",
                        getpid (), soc, name, strerror (errno));
      goto err;
    }

  internal_recv (soc, &buf, &bufsz, &msg);
  if ((msg & INTERNAL_COMM_MSG_TYPE_KB) == 0)
    {
      log_legacy_write ("[%d] plug_get_fresh_key:internal_send(%d):"
                        " Unexpected message %d", getpid (), soc, msg);
      goto err;
    }

  if (msg & INTERNAL_COMM_KB_ERROR)
    return NULL;
  if (msg & INTERNAL_COMM_KB_SENDING_STR)
    {
      char *ret = estrdup (buf);
      *type = ARG_STRING;
      efree (&buf);
      return ret;
    }
  else if (msg & INTERNAL_COMM_KB_SENDING_INT)
    {
      int ret;
      *type = ARG_INT;
      ret = atoi (buf);
      efree (&buf);
      return GSIZE_TO_POINTER (ret);
    }
err:
  if (buf != NULL)
    efree (&buf);
  return NULL;
}

static void
plug_set_replace_key (struct arglist *args, char *name, int type, void *value,
                      int replace)
{
  struct kb_item **kb = plug_get_kb (args);
  struct arglist *globals = arg_get_value (args, "globals");
  int soc = GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));
  char *str = NULL;
  int msg;

  if (name == NULL || value == NULL)
    return;

  switch (type)
    {
    case ARG_STRING:
      kb_item_add_str (kb, name, value);
      value = addslashes (value);
      str = emalloc (strlen (name) + strlen (value) + 10);
      // RATS: ignore
      snprintf (str, strlen (name) + strlen (value) + 10, "%d %s=%s;\n",
                ARG_STRING, name, (char *) value);
      if (global_nasl_debug == 1)
        log_legacy_write ("set key %s -> %s", name, (char *) value);
      efree (&value);
      break;
    case ARG_INT:
      kb_item_add_int (kb, name, GPOINTER_TO_SIZE (value));
      str = emalloc (strlen (name) + 20);
      // RATS: ignore
      snprintf (str, strlen (name) + 20, "%d %s=%d;\n", ARG_INT, name,
                (int) GPOINTER_TO_SIZE (value));
      if (global_nasl_debug == 1)
        log_legacy_write ("set key %s -> %d\n", name,
                          (int) GPOINTER_TO_SIZE (value));
      break;
    }

  if (str && soc)
    {
      int e;
      if (replace != 0)
        msg = INTERNAL_COMM_MSG_TYPE_KB | INTERNAL_COMM_KB_REPLACE;
      else
        msg = INTERNAL_COMM_MSG_TYPE_KB;

      e = internal_send (soc, str, msg);
      if (e < 0)
        log_legacy_write ("[%d] plug_set_key:internal_send(%d)['%s']: %s\n",
                          getpid (), soc, str, strerror (errno));
    }
  if (str)
    efree (&str);
}


void
plug_set_key (struct arglist *args, char *name, int type, void *value)
{
  plug_set_replace_key (args, name, type, value, 0);
}


void
plug_replace_key (struct arglist *args, char *name, int type, void *value)
{
  plug_set_replace_key (args, name, type, value, 1);
}

void
scanner_add_port (struct arglist *args, int port, char *proto)
{
  host_add_port_proto (args, port, 1, proto);
}


kb_t
plug_get_kb (struct arglist *args)
{
  return (kb_t) arg_get_value (args, "key");
}

/*
 * plug_get_key() may fork(). We use this signal handler to kill
 * its son in case the process which calls this function is killed
 * itself
 */
#ifndef OPENVASNT
static int _plug_get_key_son = 0;

static void
plug_get_key_sighand_term (int sig)
{
  int son = _plug_get_key_son;

  if (son != 0)
    {
      kill (son, SIGTERM);
      _plug_get_key_son = 0;
    }
  _exit (0);
}

static void
plug_get_key_sigchld (int sig)
{
  int status;

  wait (&status);
}

static void
sig_n (int signo, void (*fnc) (int))
{
  struct sigaction sa;

  sa.sa_handler = fnc;
  sa.sa_flags = 0;
  sigemptyset (&sa.sa_mask);
  sigaction (signo, &sa, (struct sigaction *) 0);
}

static void
sig_term (void (*fcn) (int))
{
  sig_n (SIGTERM, fcn);
}

static void
sig_alarm (void (*fcn) (int))
{
  sig_n (SIGALRM, fcn);
}

static void
sig_chld (void (*fcn) (int))
{
  sig_n (SIGCHLD, fcn);
}
#endif


void *
plug_get_key (struct arglist *args, char *name, int *type)
{
  kb_t kb = plug_get_kb (args);
  struct kb_item *res = NULL;
  int sockpair[2];
  int upstream = 0;
  char *buf = NULL;
  int bufsz = 0;


  if (type != NULL)
    *type = -1;

  if (kb == NULL)
    return NULL;

  res = kb_item_get_all (kb, name);

  if (res == NULL)
    return NULL;

  if (res->next == NULL)        /* No fork - good */
    {
      void *ret;
      if (res->type == KB_TYPE_INT)
        {
          if (type != NULL)
            *type = ARG_INT;
          ret = GSIZE_TO_POINTER (res->v.v_int);
        }
      else
        {
          if (type != NULL)
            *type = ARG_STRING;
          ret = GSIZE_TO_POINTER (res->v.v_str);
        }
      kb_item_get_all_free (res);
      return ret;
    }


  /* More than  one value - we will fork() then */
  sig_chld (plug_get_key_sigchld);
  while (res != NULL)
    {
      pid_t pid;

      socketpair (AF_UNIX, SOCK_STREAM, 0, sockpair);
      if ((pid = fork ()) == 0)
        {
          int old, soc;
          struct arglist *globals;

          close (sockpair[0]);
          globals = arg_get_value (args, "globals");
          /* FIXME: Potential problem: If "global_socket" is not set
             we are closing fd 0! */
          old = GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));
          close (old);
          soc = dup2 (sockpair[1], 4);
          close (sockpair[1]);
          arg_set_value (globals, "global_socket", sizeof (gpointer),
                         GSIZE_TO_POINTER (soc));
          arg_set_value (args, "SOCKET", sizeof (gpointer),
                         GSIZE_TO_POINTER (soc));

          srand48 (getpid () + getppid () + time (NULL)); /* RATS: ignore */

          sig_term (_exit);
          sig_alarm (_exit);
          alarm (120);

          if (res->type == KB_TYPE_INT)
            {
              int old_value = res->v.v_int;
              kb_item_rm_all (kb, name);
              kb_item_add_int (kb, name, old_value);
              if (type != NULL)
                *type = ARG_INT;
              return GSIZE_TO_POINTER (old_value);
            }
          else
            {
              char *old_value = estrdup (res->v.v_str);
              kb_item_rm_all (kb, name);
              kb_item_add_str (kb, name, old_value);
              if (type != NULL)
                *type = ARG_STRING;
              efree (&old_value);
              return kb_item_get_str (kb, name);
            }
        }
      else if (pid < 0)
        {
          log_legacy_write ("libopenvas:%s:%s(): fork() failed (%s)", __FILE__,
                            __func__, strerror (errno));
          return NULL;
        }
      else
        {
          int e;
          int status;
          struct arglist *globals;

          globals = arg_get_value (args, "globals");
          upstream =
            GPOINTER_TO_SIZE (arg_get_value (globals, "global_socket"));
          close (sockpair[1]);
          _plug_get_key_son = pid;
          sig_term (plug_get_key_sighand_term);
          for (;;)
            {
              fd_set rd;
              struct timeval tv;
              int type;
              do
                {
                  tv.tv_sec = 0;
                  tv.tv_usec = 100000;
                  FD_ZERO (&rd);
                  FD_SET (sockpair[0], &rd);
                  e = select (sockpair[0] + 1, &rd, NULL, NULL, &tv);
                }
              while (e < 0 && errno == EINTR);

              if (e > 0)
                {
                  e = internal_recv (sockpair[0], &buf, &bufsz, &type);
                  if (e < 0 || (type & INTERNAL_COMM_MSG_TYPE_CTRL))
                    {
                      e = waitpid (pid, &status, WNOHANG);
                      _plug_get_key_son = 0;
                      close (sockpair[0]);
                      sig_term (_exit);
                      break;
                    }
                  else
                    internal_send (upstream, buf, type);
                }
            }
        }
      res = res->next;
    }
  internal_send (upstream, NULL,
                 INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
  exit (0);
}

/**
 * Don't always return the first open port, otherwise
 * we might get bitten by OSes doing active SYN flood
 * countermeasures. Also, avoid returning 80 and 21 as
 * open ports, as many transparent proxies are acting for these...
 */
unsigned int
plug_get_host_open_port (struct arglist *desc)
{
  kb_t kb = plug_get_kb (desc);
  struct kb_item *res, *k;
  int open21 = 0, open80 = 0;
#define MAX_CANDIDATES 16
  u_short candidates[MAX_CANDIDATES];
  int num_candidates = 0;

  k = res = kb_item_get_pattern (kb, "Ports/tcp/*");
  if (res == NULL)
    return 0;
  else
    {
      int ret;
      char *s;

      for (;;)
        {
          s = res->name + sizeof ("Ports/tcp/") - 1;
          ret = atoi (s);
          if (ret == 21)
            open21 = 1;
          else if (ret == 80)
            open80 = 1;
          else
            {
              candidates[num_candidates++] = ret;
              if (num_candidates >= MAX_CANDIDATES)
                break;
            }
          res = res->next;
          if (res == NULL)
            break;
        }

      kb_item_get_all_free (k);
      if (num_candidates != 0)
        return candidates[lrand48 () % num_candidates]; /* RATS: ignore */
      else if (open21)
        return 21;
      else if (open80)
        return 80;
      else
        return 0;
    }

  /* Not reachable */
  return 0;
}



/** @todo
 * Those brain damaged functions should probably be in another file
 * They are use to remember who speaks SSL or not
 */

void
plug_set_port_transport (struct arglist *args, int port, int tr)
{
  char s[256];

  snprintf (s, sizeof (s), "Transports/TCP/%d", port);  /* RATS: ignore */
  plug_set_key (args, s, ARG_INT, GSIZE_TO_POINTER (tr));
}


/* Return the transport encapsulation mode (OPENVAS_ENCAPS_*) for the
   given PORT.  If no such encapsulation mode has been stored in the
   knowledge base (or its value is < 0), OPENVAS_ENCAPS_IP is
   currently returned.  */
int
plug_get_port_transport (struct arglist *args, int port)
{
  char s[256];
  int trp;

  snprintf (s, sizeof (s), "Transports/TCP/%d", port);  /* RATS: ignore */
  trp = kb_item_get_int (plug_get_kb (args), s);
  if (trp >= 0)
    return trp;
  else
    return OPENVAS_ENCAPS_IP;   /* Change this to 0 for ultra smart SSL negotiation, at the expense
                                   of possibly breaking stuff */
}

const char *
plug_get_port_transport_name (struct arglist *args, int port)
{
  return get_encaps_name (plug_get_port_transport (args, port));
}

static void
plug_set_ssl_item (struct arglist *args, char *item, char *itemfname)
{
  char s[256];
  snprintf (s, sizeof (s), "SSL/%s", item);     /* RATS: ignore */
  plug_set_key (args, s, ARG_STRING, itemfname);
}

void
plug_set_ssl_cert (struct arglist *args, char *cert)
{
  plug_set_ssl_item (args, "cert", cert);
}

void
plug_set_ssl_key (struct arglist *args, char *key)
{
  plug_set_ssl_item (args, "key", key);
}

void
plug_set_ssl_pem_password (struct arglist *args, char *key)
{
  plug_set_ssl_item (args, "password", key);
}

/** @TODO Also, all plug_set_ssl*-functions set values that are only accessed
 *        in network.c:open_stream_connection under specific conditions.
 *        Check whether these conditions can actually occur. Document the
 *        functions on the way. */
void
plug_set_ssl_CA_file (struct arglist *args, char *key)
{
  plug_set_ssl_item (args, "CA", key);
}

char *
find_in_path (char *name, int safe)
{
  char *buf = getenv ("PATH"), *pbuf, *p1, *p2;
  static char cmd[MAXPATHLEN];
  int len = strlen (name);

  if (len >= MAXPATHLEN)
    return NULL;

  if (buf == NULL)              /* Should we use a standard PATH here? */
    return NULL;

  pbuf = buf;
  while (*pbuf != '\0')
    {
      for (p1 = pbuf, p2 = cmd; *p1 != ':' && *p1 != '\0';)
        *p2++ = *p1++;
      *p2 = '\0';
      if (*p1 == ':')
        p1++;
      pbuf = p1;
      if (p2 == cmd)            /* :: found in $PATH */
        strcpy (cmd, ".");

      if (cmd[0] != '/' && safe)
        continue;
      if (p2 - cmd + 1 + len >= MAXPATHLEN)
        /* path too long: cannot be reached */
        continue;

      snprintf (p2, MAXPATHLEN, "/%s", name);   /* RATS: ignore */
      if (access (cmd, X_OK) == 0)
        {
          struct stat st;
          if (stat (cmd, &st) < 0)
            perror (cmd);
          else if (S_ISREG (st.st_mode))
            {
              *p2 = '\0';
              return cmd;
            }
        }
    }
  return NULL;
}
