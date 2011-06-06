/* OpenVAS
* $Id$
* Description: Advanced wrapper from nmap
*
* Authors:
* Henri Doreau <henri.doreau@greenbone.net>
*
* Copyright:
* Copyright (C) 2011 Greenbone Networks GmbH
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
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/

/**
 * @file nasl_builtin_nmap.c
 *
 * @brief Advanced wrapper for nmap. Perform comprehensive network scanning.
 *
 * This plugin was designed to be executed only once per network. It generates
 * the nmap command line according to the specified options, runs nmap, parses
 * the output and stores results for each host in the knowledge base.
 *
 * The plugin reconstructs host "objects" from nmap' XML output and dump then
 * into the KB.
 *
 * Parsing is performed using a two steps callbacks system.
 *   - The Glib SAX parser calls start/end_element() functions when
 *   entering/leaving a section.
 *   - On recognized sections, these first callbacks execute specialized ones
 *   (xml_open_*() and xml_close_*()).
 *
 * This system can be seen as a 1-1 mapping between XML tag names and
 * corresponding handlers.
 *
 * When leaving a XML &lt;host&gt; section, the gathered information about the
 * current host is stored into the knowledge base. Then the process is
 * repeated for the next host.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include "../misc/arglists.h"
#include "../misc/scanners_utils.h"
#include "../misc/plugutils.h"
#include "../misc/popen.h"
#include "../misc/kb.h"

#include "nasl_lex_ctxt.h"


#ifndef NDEBUG
  #define dbg(...) do { fprintf (stderr, __VA_ARGS__); } while (0)
  #define err(x) do { perror (x); } while (0)
#else
  #define dbg(...)
  #define err(x)
#endif

/* XML parser read chunks */
#define CHUNK_LEN 512

#define MAX_TRACE_HOPS  64

#define NMAP_CMD    "nmap"

/* script options */
#define PREF_TREAT_ALL_HOST_ONLINE  "Treat all hosts as online"
#define PREF_TRACEROUTE             "Trace hop path to each host"
#define PREF_NO_DNS                 "Disable DNS resolution"
#define PREF_TCP_SCANNING_TECHNIQUE "TCP scanning technique"
#define PREF_UDP_PORT_SCAN          "UDP port scan"
#define PREF_SERVICE_SCAN           "Service scan"
#define PREF_RPC_PORT_SCAN          "RPC port scan"
#define PREF_IDENTIFY_REMOTE_OS     "Identify the remote OS"
#define PREF_AGGRESSIVE_OS_DETECT   "Aggressive OS detection"
#define PREF_FRAGMENT_IP            "Fragment IP packets (bypasses firewalls)"
#define PREF_SOURCE_PORT            "Source port"
#define PREF_TIMING_POLICY          "Timing policy"
#define PREF_HOST_TIMEOUT           "Host Timeout (ms)"
#define PREF_MIN_RTT_TIMEOUT        "Min RTT Timeout (ms)"
#define PREF_MAX_RTT_TIMEOUT        "Max RTT Timeout (ms)"
#define PREF_INITIAL_RTT_TIMEOUT    "Initial RTT timeout (ms)"
#define PREF_MIN_PARALLELISM        "Ports scanned in parallel (min)"
#define PREF_MAX_PARALLELISM        "Ports scanned in parallel (max)"
#define PREF_MIN_HOSTGROUP          "Hosts scanned in parallel (min)"
#define PREF_MAX_HOSTGROUP          "Hosts scanned in parallel (max)"
#define PREF_INTERPROBE_DELAY       "Minimum wait between probes (ms)"
#define PREF_EXCLUDE_HOSTS          "Exclude hosts"
#define PREF_IMPORT_XML_FILE        "File containing XML results"

#define OPT_SET   "yes"
#define OPT_UNSET "no"


/**
 * @brief handle the results of a NSE script.
 */
struct nse_script
{
  gchar *name;              /**< NSE script id (or name) */
  gchar *output;            /**< NSE script output */
  struct nse_script *next;  /**< pointer to the next element or NULL */
};

struct traceroute_hop
{
  gchar *addr;
  gchar *host;
  gchar *rtt;
};

/**
 * @brief store port information.
 */
struct nmap_port
{
  gchar *proto;
  gchar *portno;
  gchar *state;
  gchar *service;
  struct nse_script *port_scripts;
  struct nmap_port *next;
};

/**
 * @brief store host information.
 */
struct nmap_host
{
  gchar *addr;
  gchar *state;
  gchar *best_os;
  gchar *tcpseq_index;
  gchar *tcpseq_difficulty;
  gchar *ipidseq;
  int distance;
  struct traceroute_hop trace[MAX_TRACE_HOPS];
  int os_confidence;
  struct nse_script *host_scripts;
  struct nmap_port *ports;
};

/**
 * @brief handle states for XML parsing
 */
struct nmap_parser
{
  GHashTable *opentag;
  GHashTable *closetag;

  gboolean in_host;
  gboolean in_ports;
  gboolean in_port;
  gboolean in_hostscript;
};

/**
 * @brief main nmap execution handler
 */
typedef struct
{
  /* Command line generation */
  gchar **args;
  int arg_idx;

  /* External XML file parsing */
  const gchar *filename;

  /* General execution environment */
  struct arglist *env;

  /* XML parsing states */
  struct nmap_parser parser;

  struct nmap_host tmphost;
  struct nmap_port tmpport;
} nmap_t;

/**
 * @brief describe an nmap option
 */
typedef struct
{
  gchar *optname;              /**< NASL option as exported to the user */
  gchar *flag;                      /**< nmap flag to set */
  gboolean argument_required; /**< add option value to the command line */
} nmap_opt_t;


/* --------------------- INTERNAL FUNCTIONS PROTOTYPES ---------------------- */

/*
 * Nmap handler ctor/dtor
 */
static nmap_t *nmap_create (lex_ctxt * lexic);
static void nmap_destroy (nmap_t * nmap);


/*
 * Command line generation from supplied options and parameters
 */
static int build_cmd_line (nmap_t * nmap);
static int add_arg (nmap_t * nmap, const gchar * name, const gchar * value);
static int add_nse_arguments (nmap_t * nmap);
static gchar *get_script_list (nmap_t * nmap);
static gchar *get_script_args (nmap_t * nmap);
static int add_scantype_arguments (nmap_t * nmap);
static int add_timing_arguments (nmap_t * nmap);
static int add_portrange (nmap_t * nmap);
static gchar *get_default_portrange (void);
static int setup_xml_parser (nmap_t * nmap);
static int set_opentag_callbacks (GHashTable * open);
static int set_closetag_callbacks (GHashTable * close);
static int add_target (nmap_t * nmap);
static void dbg_display_cmdline (nmap_t * nmap);


/*
 * Execution control and high level results parsing
 */
static int nmap_run_and_parse (nmap_t * nmap);
static void current_host_reset (nmap_t * nmap);
static void port_destroy (struct nmap_port *port);
static void nse_script_destroy (struct nse_script *script);
static int tmphost_add_port (nmap_t * nmap);
static int tmphost_add_nse_hostscript (nmap_t * nmap, gchar * name,
                                       gchar * output);
static int tmphost_add_nse_portscript (nmap_t * nmap, gchar * name,
                                       gchar * output);


/*
 * Top level callbacks to handle opening/closing XML elements
 */
static void
xml_start_element (GMarkupParseContext * context, const gchar * element_name,
                   const gchar ** attribute_names,
                   const gchar ** attribute_values, gpointer user_data,
                   GError ** error);
static void
xml_end_element (GMarkupParseContext * context, const gchar * element_name,
                 gpointer user_data, GError ** error);


/*
 * Callbacks for opening recognized elements
 */
static void xmltag_open_host (nmap_t * nmap, const gchar ** attrnames,
                              const gchar ** attrval);
static void xmltag_open_status (nmap_t * nmap, const gchar ** attrnames,
                                const gchar ** attrval);
static void xmltag_open_address (nmap_t * nmap, const gchar ** attrnames,
                                 const gchar ** attrval);
static void xmltag_open_ports (nmap_t * nmap, const gchar ** attrnames,
                               const gchar ** attrval);
static void xmltag_open_port (nmap_t * nmap, const gchar ** attrnames,
                              const gchar ** attrval);
static void xmltag_open_state (nmap_t * nmap, const gchar ** attrnames,
                               const gchar ** attrval);
static void xmltag_open_service (nmap_t * nmap, const gchar ** attrnames,
                                 const gchar ** attrval);
static void xmltag_open_hostscript (nmap_t * nmap, const gchar ** attrnames,
                                    const gchar ** attrval);
static void xmltag_open_osmatch (nmap_t * nmap, const gchar ** attrnames,
                                 const gchar ** attrval);
static void xmltag_open_script (nmap_t * nmap, const gchar ** attrnames,
                                const gchar ** attrval);
static void xmltag_open_tcpsequence (nmap_t * nmap, const gchar ** attrnames,
                                     const gchar ** attrval);
static void xmltag_open_ipidsequence (nmap_t * nmap, const gchar ** attrnames,
                                      const gchar ** attrval);
static void xmltag_open_hop (nmap_t * nmap, const gchar ** attrnames,
                             const gchar ** attrval);
static void xmltag_open_distance (nmap_t * nmap, const gchar ** attrnames,
                                  const gchar ** attrval);


/*
 * Callbacks for closing recognized elements
 */
static void xmltag_close_host (nmap_t * nmap);
static void xmltag_close_ports (nmap_t * nmap);
static void xmltag_close_port (nmap_t * nmap);
static void xmltag_close_hostscript (nmap_t * nmap);


/*
 * Helper function to get the strdup'ed value of a given attribute
 */
static gchar *get_attr_value (const gchar * name,
                              const gchar ** attribute_names,
                              const gchar ** attribute_values);


/*
 * Store host results in the KB
 */
static int current_host_saveall (nmap_t * nmap);
static int save_host_state (nmap_t * nmap);
static int save_open_ports (nmap_t * nmap);
static int register_service (nmap_t * nmap, struct nmap_port *p);
static int save_detected_os (nmap_t * nmap);
static int save_tcpseq_details (nmap_t * nmap);
static int save_ipidseq_details (nmap_t * nmap);
static int save_traceroute_details (nmap_t * nmap);
static int save_portscripts (nmap_t * nmap);
static int save_hostscripts (nmap_t * nmap);

/* -------------------------------------------------------------------------- */


tree_cell *
plugin_run_nmap (lex_ctxt * lexic)
{
  nmap_t *nmap;

  dbg ("Starting Nmap builtin wrapper\n");

  /* Initialize our nmap handler */
  if ((nmap = nmap_create (lexic)) == NULL)
    {
      dbg ("Unable to initialize Nmap\n");
      return NULL;
    }

  /* Execute nmap and store results */
  nmap_run_and_parse (nmap);

  /* release resources */
  nmap_destroy (nmap);

  return FAKE_CELL;
}

nmap_t *
nmap_create (lex_ctxt * lexic)
{
  gchar *pref;
  nmap_t *nmap;

  nmap = (nmap_t *) g_malloc (sizeof (nmap_t));
  if (nmap == NULL)
    {
      err ("g_malloc()");
      return NULL;
    }

  memset (nmap, 0x00, sizeof (nmap_t));

  nmap->env = lexic->script_infos;

  /* import results from external file? */
  pref = get_plugin_preference (nmap->env, PREF_IMPORT_XML_FILE);
  if (!pref || !strlen (pref))
    {
      /* no: build command line to execute */
      if (build_cmd_line (nmap) < 0)
        {
          nmap_destroy (nmap);
          return NULL;
        }

      /* Display command line to use */
      dbg ("Nmap initialized: ");
      dbg_display_cmdline (nmap);
    }
  else
    {
      /* yes: store filename */
      nmap->filename = get_plugin_preference_fname (nmap->env, pref);
      dbg ("Reading nmap results from file: %s\n", nmap->filename);
    }

  if (setup_xml_parser (nmap) < 0)
    {
      nmap_destroy (nmap);
      return NULL;
    }

  return nmap;
}

void
nmap_destroy (nmap_t * nmap)
{
  if (!nmap)
    return;

  if (nmap->args)
    {
      int i;

      for (i = 0; i < nmap->arg_idx; i++)
        g_free (nmap->args[i]);

      g_free (nmap->args);
    }

  if (nmap->parser.opentag)
    g_hash_table_destroy (nmap->parser.opentag);

  if (nmap->parser.closetag)
    g_hash_table_destroy (nmap->parser.closetag);

  g_free (nmap);
}

int
build_cmd_line (nmap_t * nmap)
{
  int i;
  /* this list handles basic options (simple flag or name/value) */
  nmap_opt_t options[] = {
    /* --- Host discovery --- */
    {PREF_TREAT_ALL_HOST_ONLINE, "-P0", FALSE},
    {PREF_TRACEROUTE, "--traceroute", FALSE},
    {PREF_NO_DNS, "-n", FALSE},

    /* --- Scan techniques --- */
    {PREF_UDP_PORT_SCAN, "-sU", FALSE},
    {PREF_SERVICE_SCAN, "-sV", FALSE},
    {PREF_RPC_PORT_SCAN, "-sR", FALSE},

    /* --- OS Detection --- */
    {PREF_IDENTIFY_REMOTE_OS, "-O", FALSE},
    {PREF_AGGRESSIVE_OS_DETECT, "--osscan-guess", FALSE},

    /* --- Firewall/IDS evasion --- */
    {PREF_FRAGMENT_IP, "-f", FALSE},
    {PREF_SOURCE_PORT, "-g", TRUE},

    /* --- Timing and performances --- */
    {PREF_HOST_TIMEOUT, "--host-timeout", TRUE},
    {PREF_MIN_RTT_TIMEOUT, "--min-rtt-timeout", TRUE},
    {PREF_MAX_RTT_TIMEOUT, "--max-rtt-timeout", TRUE},
    {PREF_INITIAL_RTT_TIMEOUT, "--initial-rtt-timeout", TRUE},
    {PREF_MIN_PARALLELISM, "--min-parallelism", TRUE},
    {PREF_MAX_PARALLELISM, "--max-parallelism", TRUE},
    {PREF_MIN_HOSTGROUP, "--min-hostgroup", TRUE},
    {PREF_MAX_HOSTGROUP, "--max-hostgroup", TRUE},
    {PREF_INTERPROBE_DELAY, "--delay", TRUE},

    /* --- Targets specification --- */
    {PREF_EXCLUDE_HOSTS, "--exclude", TRUE},

    {NULL, NULL, FALSE}
  };

  /* Nmap invocation */
  add_arg (nmap, NMAP_CMD, NULL);
  /* Enable XML output on stdout */
  add_arg (nmap, "-oX", "-");

  for (i = 0; options[i].optname; i++)
    {
      gchar *optval;

      optval = get_plugin_preference (nmap->env, options[i].optname);
      if (!optval)
        continue;

      if (options[i].argument_required)
        {
          if (strlen (optval) > 0)
            if (add_arg (nmap, options[i].flag, optval) < 0)
              return -1;
        }
      else
        {
          if (g_strcmp0 (optval, OPT_SET) == 0)
            if (add_arg (nmap, options[i].flag, NULL) < 0)
              return -1;
        }
    }

  if (add_portrange (nmap) < 0)
    return -1;

  /* Scan technique */
  if (add_scantype_arguments (nmap) < 0)
    return -1;

  /* Timing policy */
  if (add_timing_arguments (nmap) < 0)
    return -1;

  /* Script scan */
  if (add_nse_arguments (nmap) < 0)
    return -1;

  if (add_target (nmap) < 0)
    return -1;

  return 0;
}

int
add_arg (nmap_t * nmap, const gchar * name, const gchar * value)
{
  if (!name)
    return -1;

  if (!nmap->args)
    {
      /* Initial call, instanciate the NULL terminated list of arguments */
      nmap->args = (gchar **) g_malloc (sizeof (gchar **));
      if (!nmap->args)
        {
          err ("g_malloc()");
          return -1;
        }
      nmap->arg_idx = 0;
    }

  if (!value)
    {
      /* simple flag (no value) */
      nmap->args = g_realloc (nmap->args,
                              (nmap->arg_idx + 2) * sizeof (gchar *));
      nmap->args[nmap->arg_idx++] = g_strdup (name);
    }
  else
    {
      /* name->value argument */
      nmap->args = g_realloc (nmap->args,
                              (nmap->arg_idx + 3) * sizeof (gchar *));
      nmap->args[nmap->arg_idx++] = g_strdup (name);
      nmap->args[nmap->arg_idx++] = g_strdup (value);
    }

  /* NULL-terminate the list */
  nmap->args[nmap->arg_idx] = NULL;

  return 1;
}

int
add_nse_arguments (nmap_t * nmap)
{
  gchar *pscript, *pargs;

  pscript = get_script_list (nmap);
  pargs = get_script_args (nmap);
  if (strlen (pscript))
    {
      /* Add script flags if user requested some NSE */
      add_arg (nmap, "--script", pscript);

      if (strlen (pargs))
        add_arg (nmap, "--script-args", pargs);
    }
  g_free (pscript);
  g_free (pargs);

  return 1;
}

gchar *
get_script_list (nmap_t * nmap)
{
  struct kb_item **kb = plug_get_kb (nmap->env);
  struct kb_item *top, *res;
  gchar **scriptv, *scriptstr;
  int i = 0;

  scriptv = NULL;

  /* Read list of scripts from the KB */
  top = res = kb_item_get_all (kb, "NmapNSE/scripts");
  while (res)
    {
      scriptv = (gchar **) g_realloc (scriptv, (i + 1) * sizeof (gchar *));
      scriptv[i++] = g_strdup (res->v.v_str);
      res = res->next;
    }

  scriptv = (gchar **) g_realloc (scriptv, (i + 1) * sizeof (gchar *));
  scriptv[i] = NULL;

  kb_item_get_all_free (top);

  scriptstr = g_strjoinv (",", scriptv);

  for (i = 0; scriptv[i]; i++)
    g_free (scriptv[i]);

  g_free (scriptv);

  return scriptstr;
}

gchar *
get_script_args (nmap_t * nmap)
{
  struct kb_item **kb = plug_get_kb (nmap->env);
  struct kb_item *top, *res;
  gchar **argv, *argstr;
  int i = 0;

  argv = NULL;

  top = res = kb_item_get_all (kb, "NmapNSE/arguments");
  while (res)
    {
      argv = (gchar **) g_realloc (argv, (i + 1) * sizeof (gchar *));
      argv[i++] = g_strdup (res->v.v_str);
      res = res->next;
    }

  argv = (gchar **) g_realloc (argv, (i + 1) * sizeof (gchar *));
  argv[i] = NULL;

  kb_item_get_all_free (top);

  argstr = g_strjoinv (",", argv);

  for (i = 0; argv[i]; i++)
    g_free (argv[i]);
  g_free (argv);

  return argstr;
}

int
add_scantype_arguments (nmap_t * nmap)
{
  int i;
  gchar *scantype;
  nmap_opt_t flagmap[] = {
    {"connect()", "-sT", FALSE},
    {"SYN", "-sS", FALSE},
    {"ACK", "-sA", FALSE},
    {"FIN", "-sF", FALSE},
    {"Window", "-sW", FALSE},
    {"Maimon", "-sM", FALSE},
    {"Xmas tree", "-sX", FALSE},
    {"Null", "-sN", FALSE},
    {"SCTP Init", "-sY", FALSE},
    {"SCTP COOKIE_ECHO", "-sZ", FALSE},
    {NULL, NULL, FALSE}
  };

  scantype = get_plugin_preference (nmap->env, PREF_TCP_SCANNING_TECHNIQUE);
  if (!scantype)
    return -1;

  for (i = 0; flagmap[i].optname; i++)
    if (g_strcmp0 (scantype, flagmap[i].optname) == 0)
      return add_arg (nmap, flagmap[i].flag, NULL);

  return -1;
}

int
add_timing_arguments (nmap_t * nmap)
{
  int i;
  gchar *timing;
  nmap_opt_t flagmap[] = {
    {"Paranoid", "-T0", FALSE},
    {"Sneaky", "-T1", FALSE},
    {"Polite", "-T2", FALSE},
    {"Normal", "-T3", FALSE},
    {"Aggressive", "-T4", FALSE},
    {"Insane", "-T5", FALSE},
    {NULL, NULL, FALSE}
  };

  timing = get_plugin_preference (nmap->env, PREF_TIMING_POLICY);
  if (!timing)
    return -1;

  for (i = 0; flagmap[i].optname; i++)
    if (g_strcmp0 (timing, flagmap[i].optname) == 0)
      return add_arg (nmap, flagmap[i].flag, NULL);

  return -1;
}

int
add_portrange (nmap_t * nmap)
{
  int ret;
  struct arglist *pref;
  gchar *portrange;

  pref = arg_get_value (nmap->env, "preferences");
  if (!pref)
    {
      dbg ("Invalid environment: unavailable \"preferences\"\n");
      return -1;
    }

  portrange = arg_get_value (pref, "port_range");
  if (!portrange)
    {
      dbg ("Invalid environment: unavailable \"port_range\"\n");
      return -1;
    }

  if (g_strcmp0 (portrange, "default") == 0)
    {
      gchar *pr_default = get_default_portrange ();

      if (!pr_default)
        {
          dbg ("Invalid default port range\n");
          return -1;
        }
      ret = add_arg (nmap, "-p", pr_default);
      g_free (pr_default);
    }
  else
    ret = add_arg (nmap, "-p", portrange);

  return ret;
}

gchar *
get_default_portrange (void)
{
  gchar *portrange = NULL;
  unsigned short *ports;
  int i, plen = sizeof (ports) / sizeof (unsigned short);
  int start = -1, stop = -1;

  ports = getpts ("default", &plen);
  if (!ports || !plen)
    return NULL;

  int cmp (const void *p1, const void *p2)
  {
    unsigned short *pp1 = (unsigned short *) p1;
    unsigned short *pp2 = (unsigned short *) p2;

    return (*pp1) - (*pp2);
  }
  qsort (ports, plen, sizeof (unsigned short), cmp);

  for (i = 0; i < plen; i++)
    {
      gboolean last_run = (i == plen - 1);
      gchar *tmp, chunk[16];

      if (start == -1)
        {
          start = stop = ports[i];
          if (!last_run)
            continue;
        }
      else if (ports[i] == stop + 1)
        {
          stop = ports[i];
          if (!last_run)
            continue;
        }

      if (start != stop)
        g_snprintf (chunk, sizeof (chunk), "%d-%d", start, stop);
      else
        g_snprintf (chunk, sizeof (chunk), "%d", start);

      start = stop = ports[i];

      if (portrange)
        tmp = g_strdup_printf ("%s,%s", portrange, chunk);
      else
        tmp = g_strdup_printf ("%s", chunk);
      g_free (portrange);        /* g_free'ing NULL pointers is harmless */
      portrange = tmp;
    }

  return portrange;
}

int
setup_xml_parser (nmap_t * nmap)
{
  /* reset internal states */
  nmap->parser.in_host = FALSE;
  nmap->parser.in_ports = FALSE;
  nmap->parser.in_port = FALSE;
  nmap->parser.in_hostscript = FALSE;

  nmap->parser.opentag = g_hash_table_new (g_str_hash, g_str_equal);
  nmap->parser.closetag = g_hash_table_new (g_str_hash, g_str_equal);
  if (!nmap->parser.opentag || !nmap->parser.closetag)
    {
      err ("HashTables allocation failure:");
      return -1;    /* allocated resources will be free'd in nmap_destroy() */
    }

  set_opentag_callbacks (nmap->parser.opentag);
  set_closetag_callbacks (nmap->parser.closetag);
  return 1;
}

int
set_opentag_callbacks (GHashTable * open)
{
  const struct
  {
    const gchar *tag;
    void (*func) (nmap_t *, const gchar **, const gchar **);
  } callbacks[] = {
    {"hop", xmltag_open_hop},
    {"osmatch", xmltag_open_osmatch},
    {"port", xmltag_open_port},
    {"service", xmltag_open_service},
    {"state", xmltag_open_state},
    {"status", xmltag_open_status},
    {"host", xmltag_open_host},
    {"address", xmltag_open_address},
    {"script", xmltag_open_script},
    {"ports", xmltag_open_ports},
    {"distance", xmltag_open_distance},
    {"hostscript", xmltag_open_hostscript},
    {"tcpsequence", xmltag_open_tcpsequence},
    {"ipidsequence", xmltag_open_ipidsequence},
    {NULL, NULL}
  };
  int i;

  for (i = 0; callbacks[i].tag; i++)
    g_hash_table_insert (open, (void *) callbacks[i].tag, callbacks[i].func);

  return 1;
}

int
set_closetag_callbacks (GHashTable * close)
{
  const struct
  {
    const gchar *tag;
    void (*func) (nmap_t *);
  } callbacks[] = {
    {"host", xmltag_close_host},
    {"ports", xmltag_close_ports},
    {"port", xmltag_close_port},
    {"hostscript", xmltag_close_hostscript},
    {NULL, NULL}
  };
  int i;

  for (i = 0; callbacks[i].tag; i++)
    g_hash_table_insert (close, (void *) callbacks[i].tag, callbacks[i].func);

  return 1;
}

int
add_target (nmap_t * nmap)
{
  struct arglist *globals;
  gchar *network;

  globals = arg_get_value (nmap->env, "globals");
  if (!globals)
    {
      dbg ("Invalid environment: unavailable \"globals\"\n");
      return -1;
    }

  network = arg_get_value (globals, "network_targets");
  if (!network)
    {
      dbg ("Invalid environment: unavailable \"network_targets\"\n");
      return -1;
    }

  return add_arg (nmap, network, NULL);
}

void
dbg_display_cmdline (nmap_t * nmap)
{
  int i;

  for (i = 0; nmap->args[i]; i++)
    dbg ("%s ", nmap->args[i]);

  if (i == 0)
    dbg ("<empty>");

  dbg ("\n");
}

int
nmap_run_and_parse (nmap_t * nmap)
{
  FILE *fproc;
  size_t len;
  pid_t pid;
  gchar chunk[CHUNK_LEN];
  GMarkupParseContext *ctx;
  const GMarkupParser callbacks = {
    xml_start_element,
    xml_end_element,
    NULL,     /* text */
    NULL,     /* passthrough */
    NULL      /* error */
  };

  if (nmap->filename)
    /* read results from external file */
    fproc = fopen (nmap->filename, "r");
  else
    /* execute nmap and read results from the process output */
    fproc = openvas_popen4 (nmap->args[0], nmap->args, &pid, 0);

  if (!fproc)
    {
      err ("nmap_run_and_parse()");
      return -1;
    }

  ctx = g_markup_parse_context_new (&callbacks, 0, nmap, NULL);

  while ((len = fread (chunk, sizeof (gchar), CHUNK_LEN, fproc)) > 0)
    {
      GError *err = NULL;

      if (!g_markup_parse_context_parse (ctx, chunk, len, &err))
        {
          if (err)
            {
              dbg ("g_markup_parse_context_parse() failed (%s)\n",
                   err->message);
              g_error_free (err);

              /* display the problematic chunk */
              chunk[len] = '\0';
              dbg ("Error occured while parsing: %s\n", chunk);
            }
          break;
        }
    }

  if (nmap->filename)
    fclose (fproc);
  else
    openvas_pclose (fproc, pid);

  g_markup_parse_context_free (ctx);

  return 1;
}

void
current_host_reset (nmap_t * nmap)
{
  int i;
  struct nmap_port *p;
  struct nse_script *s;

  g_free (nmap->tmphost.addr);
  g_free (nmap->tmphost.state);
  g_free (nmap->tmphost.best_os);
  g_free (nmap->tmphost.tcpseq_index);
  g_free (nmap->tmphost.tcpseq_difficulty);
  g_free (nmap->tmphost.ipidseq);

  for (i = 0; i < MAX_TRACE_HOPS; i++)
    {
      g_free (nmap->tmphost.trace[i].addr);
      g_free (nmap->tmphost.trace[i].rtt);
      g_free (nmap->tmphost.trace[i].host);
    }

  p = nmap->tmphost.ports;
  while (p != NULL)
    {
      struct nmap_port *next;

      next = p->next;
      port_destroy (p);
      p = next;
    }

  s = nmap->tmphost.host_scripts;
  while (s != NULL)
    {
      struct nse_script *next;

      next = s->next;
      nse_script_destroy (s);
      s = next;
    }

  memset (&nmap->tmphost, 0x00, sizeof (struct nmap_host));
}

void
port_destroy (struct nmap_port *port)
{
  if (port)
    {
      struct nse_script *s;

      g_free (port->proto);
      g_free (port->portno);
      g_free (port->state);
      g_free (port->service);

      s = port->port_scripts;
      while (s != NULL)
        {
          struct nse_script *next;

          next = s->next;
          nse_script_destroy (s);
          s = next;
        }
      g_free (port);
    }
}

void
nse_script_destroy (struct nse_script *script)
{
  if (script)
    {
      g_free (script->name);
      g_free (script->output);
      g_free (script);
    }
}

int
tmphost_add_port (nmap_t * nmap)
{
  struct nmap_port *newport;

  newport = (struct nmap_port *) g_malloc (sizeof (struct nmap_port));
  if (!newport)
    {
      err ("g_malloc()");
      return -1;
    }

  memcpy (newport, &nmap->tmpport, sizeof (struct nmap_port));
  newport->next = nmap->tmphost.ports;
  nmap->tmphost.ports = newport;

  return 1;
}

int
tmphost_add_nse_hostscript (nmap_t * nmap, gchar * name, gchar * output)
{
  struct nse_script *s;

  s = (struct nse_script *) g_malloc (sizeof (struct nse_script));
  if (!s)
    {
      err ("g_malloc()");
      return -1;
    }

  s->name = name;
  s->output = output;
  s->next = nmap->tmphost.host_scripts;
  nmap->tmphost.host_scripts = s;

  return 1;
}

int
tmphost_add_nse_portscript (nmap_t * nmap, gchar * name, gchar * output)
{
  struct nse_script *s;

  s = (struct nse_script *) g_malloc (sizeof (struct nse_script));
  if (!s)
    {
      err ("g_malloc()");
      return -1;
    }

  s->name = name;
  s->output = output;
  s->next = nmap->tmpport.port_scripts;
  nmap->tmpport.port_scripts = s;

  return 1;
}

void
xml_start_element (GMarkupParseContext * context, const gchar * element_name,
                   const gchar ** attribute_names,
                   const gchar ** attribute_values, gpointer user_data,
                   GError ** error)
{
  nmap_t *nmap = (nmap_t *) user_data;
  void (*callback) (nmap_t *, const gchar **, const gchar **);

  callback = g_hash_table_lookup (nmap->parser.opentag, element_name);
  if (callback)
    callback (nmap, attribute_names, attribute_values);
}

void
xml_end_element (GMarkupParseContext * context, const gchar * element_name,
                 gpointer user_data, GError ** error)
{
  nmap_t *nmap = (nmap_t *) user_data;
  void (*callback) (nmap_t *);

  callback = g_hash_table_lookup (nmap->parser.closetag, element_name);
  if (callback)
    callback (nmap);
}

void
xmltag_open_host (nmap_t * nmap, const gchar ** attrnames,
                  const gchar ** attrval)
{
  nmap->parser.in_host = TRUE;
}

void
xmltag_open_status (nmap_t * nmap, const gchar ** attrnames,
                    const gchar ** attrval)
{
  if (!nmap->parser.in_host)
    dbg ("Error: opening <status> tag out of host description\n");
  else
    nmap->tmphost.state = get_attr_value ("state", attrnames, attrval);
}

void
xmltag_open_address (nmap_t * nmap, const gchar ** attrnames,
                     const gchar ** attrval)
{
  if (!nmap->parser.in_host)
    dbg ("Error: opening <address> tag out of host description\n");
  else
    nmap->tmphost.addr = get_attr_value ("addr", attrnames, attrval);
}

void
xmltag_open_ports (nmap_t * nmap, const gchar ** attrnames,
                   const gchar ** attrval)
{
  nmap->parser.in_ports = TRUE;
}

void
xmltag_open_port (nmap_t * nmap, const gchar ** attrnames,
                  const gchar ** attrval)
{
  nmap->parser.in_port = TRUE;
  nmap->tmpport.proto = get_attr_value ("protocol", attrnames, attrval);
  nmap->tmpport.portno = get_attr_value ("portid", attrnames, attrval);
}

void
xmltag_open_state (nmap_t * nmap, const gchar ** attrnames,
                   const gchar ** attrval)
{
  if (!nmap->parser.in_port || !nmap->tmpport.proto || !nmap->tmpport.portno)
    dbg ("Error: opening <state> tag out of port description\n");
  else
    nmap->tmpport.state = get_attr_value ("state", attrnames, attrval);
}

void
xmltag_open_service (nmap_t * nmap, const gchar ** attrnames,
                     const gchar ** attrval)
{
  if (!nmap->parser.in_port || !nmap->tmpport.proto || !nmap->tmpport.portno)
    dbg ("Error: opening <service> tag out of port description\n");
  else
    nmap->tmpport.service = get_attr_value ("name", attrnames, attrval);
}

void
xmltag_open_hostscript (nmap_t * nmap, const gchar ** attrnames,
                        const gchar ** attrval)
{
  nmap->parser.in_hostscript = TRUE;
}

void
xmltag_open_osmatch (nmap_t * nmap, const gchar ** attrnames,
                     const gchar ** attrval)
{
  gchar *confstr;

  confstr = get_attr_value ("accuracy", attrnames, attrval);
  if (confstr)
    {
      int confidence;

      confidence = atoi (confstr);
      if (confidence > nmap->tmphost.os_confidence)
        {
          g_free (nmap->tmphost.best_os);
          nmap->tmphost.best_os = get_attr_value ("name", attrnames, attrval);
          nmap->tmphost.os_confidence = confidence;
        }

      g_free (confstr);
    }
}

void
xmltag_open_script (nmap_t * nmap, const gchar ** attrnames,
                    const gchar ** attrval)
{
  gchar *name, *output;

  if (!nmap->parser.in_host)
    return;

  name = get_attr_value ("id", attrnames, attrval);
  output = get_attr_value ("output", attrnames, attrval);

  if (nmap->parser.in_port)
    tmphost_add_nse_portscript (nmap, name, output);
  else
    tmphost_add_nse_hostscript (nmap, name, output);
}

void
xmltag_open_tcpsequence (nmap_t * nmap, const gchar ** attrnames,
                         const gchar ** attrval)
{
  if (!nmap->parser.in_host)
    return;

  nmap->tmphost.tcpseq_index = get_attr_value ("index", attrnames, attrval);
  nmap->tmphost.tcpseq_difficulty =
    get_attr_value ("difficulty", attrnames, attrval);
}

void
xmltag_open_ipidsequence (nmap_t * nmap, const gchar ** attrnames,
                          const gchar ** attrval)
{
  if (!nmap->parser.in_host)
    return;

  nmap->tmphost.ipidseq = get_attr_value ("class", attrnames, attrval);
}

void
xmltag_open_distance (nmap_t * nmap, const gchar ** attrnames,
                      const gchar ** attrval)
{
  gchar *diststr;

  if (!nmap->parser.in_host)
    return;

  diststr = get_attr_value ("value", attrnames, attrval);
  if (diststr)
    {
      nmap->tmphost.distance = atoi (diststr);
      g_free (diststr);
    }
}

void
xmltag_open_hop (nmap_t * nmap, const gchar ** attrnames,
                 const gchar ** attrval)
{
  int ttl;
  gchar *ttl_str;

  if (!nmap->parser.in_host)
    return;

  ttl_str = get_attr_value ("ttl", attrnames, attrval);
  ttl = atoi (ttl_str) - 1;        /* decrease ttl by one to use it as index */
  g_free (ttl_str);

  if (ttl < MAX_TRACE_HOPS)
    {
      if (!nmap->tmphost.trace[ttl].addr && !nmap->tmphost.trace[ttl].host
          && !nmap->tmphost.trace[ttl].rtt)
        {
          nmap->tmphost.trace[ttl].addr = get_attr_value ("ipaddr", attrnames,
                                                          attrval);
          nmap->tmphost.trace[ttl].host = get_attr_value ("host", attrnames,
                                                          attrval);
          nmap->tmphost.trace[ttl].rtt = get_attr_value ("rtt", attrnames,
                                                         attrval);
        }
      else
        dbg ("Inconsistent results: duplicate traceroute information!");
    }
  else
    dbg ("Trace TTL out of bounds: %d (max=%d)", ttl, MAX_TRACE_HOPS);
}

void
xmltag_close_host (nmap_t * nmap)
{
  nmap->parser.in_host = FALSE;
  current_host_saveall (nmap);
  current_host_reset (nmap);
}

void
xmltag_close_ports (nmap_t * nmap)
{
  nmap->parser.in_ports = FALSE;
}

void
xmltag_close_port (nmap_t * nmap)
{
  nmap->parser.in_port = FALSE;
  tmphost_add_port (nmap);
  memset (&nmap->tmpport, 0x00, sizeof (struct nmap_port));
}

void
xmltag_close_hostscript (nmap_t * nmap)
{
  nmap->parser.in_hostscript = FALSE;
}

gchar *
get_attr_value (const gchar * name, const gchar **
                attribute_names, const gchar ** attribute_values)
{
  int i;

  for (i = 0; attribute_names[i]; i++)
    if (g_strcmp0 (attribute_names[i], name) == 0)
      return g_strdup (attribute_values[i]);
  return NULL;
}

int
current_host_saveall (nmap_t * nmap)
{
  /* Host state: dead or alive */
  save_host_state (nmap);

  /* Open ports and services (all protocols included) */
  save_open_ports (nmap);

  /* OS fingerprinting results */
  save_detected_os (nmap);

  /* TCP/IP sensitive fields details */
  save_tcpseq_details (nmap);
  save_ipidseq_details (nmap);

  /* Traceroute */
  save_traceroute_details (nmap);

  /* NSE results */
  save_hostscripts (nmap);
  save_portscripts (nmap);

  return 1;
}

int
save_host_state (nmap_t * nmap)
{
  gchar key[32];

  if (!nmap->tmphost.state)
    return -1;

  g_snprintf (key, sizeof (key), "%s/Host/State", nmap->tmphost.addr);
  plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.state);
  return 1;
}

int
save_open_ports (nmap_t * nmap)
{
  struct nmap_port *p;

  for (p = nmap->tmphost.ports; p != NULL; p = p->next)
    {
      if (g_strcmp0 (p->state, "open") == 0)
        {
          gchar key[64];

          g_snprintf (key, sizeof (key), "%s/Ports/%s/%s", nmap->tmphost.addr,
                      p->proto, p->portno);
          plug_set_key (nmap->env, key, ARG_INT, (void *) 1);

          /* Register detected service */
          register_service (nmap, p);
        }
    }
  return 1;
}

int
register_service (nmap_t * nmap, struct nmap_port *p)
{
  gchar key[64];

  if (!p->portno || !p->proto || !p->service)
    return -1;

  /* TCP services aren't stored with the same syntax than the other layer 4
   * protocols. */
  if (g_strcmp0 (p->proto, "tcp") == 0)
    g_snprintf (key, sizeof (key), "%s/Services/%s", nmap->tmphost.addr,
                p->service);
  else
    g_snprintf (key, sizeof (key), "%s/Services/%s/%s", nmap->tmphost.addr,
                p->proto, p->service);
  plug_set_key (nmap->env, key, ARG_INT, GINT_TO_POINTER (atoi (p->portno)));

  /* The service detection system requires discovered services to be
   * registered under the "Known" label too */
  g_snprintf (key, sizeof (key), "%s/Known/%s/%s", nmap->tmphost.addr,
              p->proto, p->portno);
  plug_replace_key (nmap->env, key, ARG_STRING, p->service);

  return 1;
}

int
save_detected_os (nmap_t * nmap)
{
  gchar key[32];

  if (!nmap->tmphost.best_os)
    return -1;

  g_snprintf (key, sizeof (key), "%s/Host/OS", nmap->tmphost.addr);
  plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.best_os);

  return 1;
}

int
save_tcpseq_details (nmap_t * nmap)
{
  gchar key[64];

  if (!nmap->tmphost.tcpseq_index || !nmap->tmphost.tcpseq_difficulty)
    return -1;

  g_snprintf (key, sizeof (key), "%s/Host/tcp_seq_index", nmap->tmphost.addr);
  plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.tcpseq_index);

  g_snprintf (key, sizeof (key), "%s/Host/tcp_seq_difficulty",
              nmap->tmphost.addr);
  plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.tcpseq_difficulty);

  return 1;
}

int
save_ipidseq_details (nmap_t * nmap)
{
  gchar key[32];

  if (!nmap->tmphost.ipidseq)
    return -1;

  g_snprintf (key, sizeof (key), "%s/Host/ipidseq", nmap->tmphost.addr);
  plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.ipidseq);

  return 1;
}

int
save_traceroute_details (nmap_t * nmap)
{
  int i;
  gchar key[64];

  if (!nmap->tmphost.distance || nmap->tmphost.distance >= MAX_TRACE_HOPS)
    return -1;

  g_snprintf (key, sizeof (key), "%s/Host/distance", nmap->tmphost.addr);
  plug_set_key (nmap->env, key, ARG_INT,
                GINT_TO_POINTER (nmap->tmphost.distance));

  for (i = 0; i < nmap->tmphost.distance; i++)
    {
      g_snprintf (key, sizeof (key), "%s/Host/traceroute/hops/%d",
                  nmap->tmphost.addr, i + 1);
      plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.trace[i].addr);

      g_snprintf (key, sizeof (key), "%s/Host/traceroute/hops/%d/rtt",
                  nmap->tmphost.addr, i + 1);
      plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.trace[i].rtt);

      g_snprintf (key, sizeof (key), "%s/Host/traceroute/hops/%d/host",
                  nmap->tmphost.addr, i + 1);
      plug_set_key (nmap->env, key, ARG_STRING, nmap->tmphost.trace[i].host);
    }

  return 1;
}

int
save_portscripts (nmap_t * nmap)
{
  struct nmap_port *port;

  for (port = nmap->tmphost.ports; port != NULL; port = port->next)
    {
      struct nse_script *script;

      for (script = port->port_scripts; script; script = script->next)
        {
          gchar key[128], portspec[16];

          g_snprintf (key, sizeof (key), "%s/NmapNSE/results/%s",
                      nmap->tmphost.addr, script->name);

          g_snprintf (portspec, sizeof (portspec), "%s/%s", port->proto,
                      port->portno);
          plug_set_key (nmap->env, key, ARG_STRING, portspec);

          g_strlcat (key, "/", sizeof (key));
          g_strlcat (key, portspec, sizeof (key));
          plug_set_key (nmap->env, key, ARG_STRING, script->output);
        }
    }
  return 1;
}

int
save_hostscripts (nmap_t * nmap)
{
  struct nse_script *script;

  for (script = nmap->tmphost.host_scripts; script != NULL;
       script = script->next)
    {
      gchar key[128];

      g_snprintf (key, sizeof (key), "%s/NmapNSE/results/hostscripts/%s",
                  nmap->tmphost.addr, script->name);
      plug_set_key (nmap->env, key, ARG_STRING, script->output);
    }
  return 1;
}

