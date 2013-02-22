/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2005 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

 /**
  * @file
  * Source of the standalone NASL interpreter of OpenVAS.
  */

#include <signal.h>             /* for SIGINT */
#include <string.h>             /* for strlen */
#include <stdlib.h>             /* for exit */
#include <unistd.h>             /* for geteuid */
#ifdef HAVE_LIBSSH
# include <libssh/libssh.h>     /* for ssh_version */
#endif

#include "hosts_gatherer.h"
#include "kb.h"                 /* for kb_new */
#include "network.h"
#include "system.h"             /* for efree */

#include "nasl.h"
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "../base/gpgme_util.h" /* for gpgme_check_version */

#include <glib.h>

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif


extern char *nasl_version ();
extern int execute_instruction (struct arglist *, char *);
void exit_nasl (struct arglist *, int);


int safe_checks_only = 0;

static struct arglist *
init_hostinfos (char *hostname, struct in6_addr *ip)
{
  struct arglist *hostinfos;
  struct arglist *ports;

  hostinfos = emalloc (sizeof (struct arglist));
  arg_add_value (hostinfos, "FQDN", ARG_STRING, strlen (hostname), hostname);
  arg_add_value (hostinfos, "NAME", ARG_STRING, strlen (hostname), hostname);
  arg_add_value (hostinfos, "IP", ARG_PTR, sizeof (struct in6_addr), ip);
  ports = emalloc (sizeof (struct arglist));
  arg_add_value (hostinfos, "PORTS", ARG_ARGLIST, sizeof (struct arglist),
                 ports);
  return (hostinfos);
}

void
sighandler (int s)
{
  exit (0);
}

static void
my_gnutls_log_func (int level, const char *text)
{
  fprintf (stderr, "[%d] (%d) %s", getpid (), level, text);
  if (*text && text[strlen (text) -1] != '\n')
    putc ('\n', stderr);
}

struct arglist *
init (char *hostname, struct in6_addr ip)
{
  struct arglist *script_infos = emalloc (sizeof (struct arglist));
  struct arglist *prefs = emalloc (sizeof (struct arglist));
  struct in6_addr *pip = emalloc (sizeof (*pip));
  memcpy (pip, &ip, sizeof (struct in6_addr));

  arg_add_value (script_infos, "standalone", ARG_INT, sizeof (int), (void *) 1);
  arg_add_value (prefs, "checks_read_timeout", ARG_STRING, 4, estrdup ("5"));
  arg_add_value (script_infos, "preferences", ARG_ARGLIST, -1, prefs);
  arg_add_value (script_infos, "key", ARG_PTR, -1, kb_new ());

  if (safe_checks_only != 0)
    arg_add_value (prefs, "safe_checks", ARG_STRING, 3, estrdup ("yes"));

  arg_add_value (script_infos, "HOSTNAME", ARG_ARGLIST, -1,
                 init_hostinfos (hostname, pip));

  return script_infos;
}

extern FILE *nasl_trace_fp;

/**
 * @brief Main of the standalone nasl interpretor.
 * @return The number of times a NVT was launched
 *         (should be (number of targets) * (number of NVTS provided)).
 */
int
main (int argc, char **argv)
{
  struct arglist *script_infos;
  static gchar *target = NULL;
  gchar *default_target = "127.0.0.1";
  struct hg_globals *hg_globals;
  struct in6_addr ip6;
  int start, n;
  char hostname[1024];
  int mode = 0;
  int err = 0;

  static gboolean display_version = FALSE;
  static gboolean description_only = FALSE;
  static gboolean parse_only = FALSE;
  static gboolean do_lint = FALSE;
  static gchar *trace_file = NULL;
  static gboolean with_safe_checks = FALSE;
  static gboolean authenticated_mode = FALSE;
  static gchar *include_dir = NULL;
  static gchar **nasl_filenames = NULL;
  static int debug_tls = 0;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &display_version,
     "Display version information", NULL},
    {"description", 'D', 0, G_OPTION_ARG_NONE, &description_only,
     "Only run the 'description' part of the script", NULL},
    {"parse", 'p', 0, G_OPTION_ARG_NONE, &parse_only,
     "Only parse the script, don't execute it", NULL},
    {"lint", 'L', 0, G_OPTION_ARG_NONE, &do_lint,
     "'lint' the script (extended checks)", NULL},
    {"target", 't', 0, G_OPTION_ARG_STRING, &target,
     "Execute the scripts against <target>", "<target>"},
    {"trace", 'T', 0, G_OPTION_ARG_FILENAME, &trace_file,
     "Log actions to <file> (or '-' for stderr)", "<file>"},
    {"safe", 's', 0, G_OPTION_ARG_NONE, &with_safe_checks,
     "Specifies that the script should be run with 'safe checks' enabled",
     NULL},
    {"authenticated", 'X', 0, G_OPTION_ARG_NONE, &authenticated_mode,
     "Run the script in 'authenticated' mode", NULL},
    {"include-dir", 'i', 0, G_OPTION_ARG_STRING, &include_dir,
     "Search for includes in <dir>", "<dir>"},
    {"debug-tls", 0, 0, G_OPTION_ARG_INT, &debug_tls,
     "Enable TLS debugging at <level>", "<level>"},
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &nasl_filenames,
     NULL, NULL},
    {NULL}
  };

  option_context =
    g_option_context_new ("- standalone NASL interpreter for OpenVAS");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_print ("%s\n\n", error->message);
      exit (0);
    }
  g_option_context_free (option_context);
 /*--------------------------------------------
 	Command-line options
  ---------------------------------------------*/

  if (display_version)
    {
      printf ("openvas-nasl %s\n", nasl_version ());
      if (debug_tls)
        {
          printf ("gnutls %s\n", gnutls_check_version (NULL));
#       ifdef HAVE_LIBSSH
          printf ("libssh %s\n", ssh_version (0));
#       endif
          printf ("gpgme %s\n", gpgme_check_version (NULL));
        }
      else
        putchar ('\n');
      printf ("Copyright (C) 2002 - 2004 Tenable Network Security\n");
      printf ("Copyright (C) 2013 Greenbone Networks GmbH\n\n");
      exit (0);
    }
  mode |= NASL_COMMAND_LINE;
  if (authenticated_mode)
    mode |= NASL_ALWAYS_SIGNED;
  if (description_only)
    mode |= NASL_EXEC_DESCR;
  if (do_lint)
    mode |= NASL_LINT;
  if (parse_only)
    mode |= NASL_EXEC_PARSE_ONLY;
  if (trace_file)
    {
      if (!strcmp (trace_file, "-"))
        nasl_trace_fp = stderr;
      else
        {
          FILE *fp = fopen (trace_file, "w");
          if (fp == NULL)
            {
              perror (optarg);
              exit (2);
            }
#ifdef _IOLBF
          setvbuf (fp, NULL, _IOLBF, BUFSIZ);
#else
          setlinebuf (fp);
#endif
          nasl_trace_fp = fp;
        }
    }
  if (with_safe_checks)
    safe_checks_only++;

  openvas_SSL_init ();
  if (!nasl_filenames)
    {
      fprintf (stderr, "Error. No input file specified !\n");
      exit (1);
    }

#ifndef _CYGWIN_
  if (!(mode & (NASL_EXEC_PARSE_ONLY | NASL_LINT)) && geteuid ())
    {
      fprintf (stderr, "** WARNING : packet forgery will not work\n");
      fprintf (stderr, "** as NASL is not running as root\n");
    }
  signal (SIGINT, sighandler);
  signal (SIGTERM, sighandler);
  signal (SIGPIPE, SIG_IGN);
#endif

  if (debug_tls)
    {
      gnutls_global_set_log_function (my_gnutls_log_func);
      gnutls_global_set_log_level (debug_tls);
    }

  if (!target)
    target = g_strdup (default_target);

  start = 0;

  hg_globals = hg_init (target, 4);
  efree (&target);

  // for absolute and relative paths
  add_nasl_inc_dir ("");
  if (include_dir != NULL)
    {
      add_nasl_inc_dir (include_dir);
    }

  while (hg_next_host (hg_globals, &ip6, hostname, sizeof (hostname)) >= 0)
    {
      script_infos = init (hostname, ip6);
      n = start;
      while (nasl_filenames[n])
        {
          if (exec_nasl_script (script_infos, nasl_filenames[n], mode) < 0)
            err++;
          n++;
        }
    }

  if (nasl_trace_fp != NULL)
    fflush (nasl_trace_fp);

  hg_cleanup (hg_globals);

  return err;
}
