/* Copyright (C) 2020-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include "boreas_io.h"

#include "../base/prefs.h" /* for prefs_get() */
#include "alivedetection.h"
#include "util.h"

#include <glib/gprintf.h>
#include <stdlib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

scan_restrictions_t scan_restrictions;

/**
 * @brief Check if max_scan_hosts alive hosts reached.
 *
 * @return TRUE if max_scan_hosts alive hosts reached, else FALSE.
 */
static gboolean
max_scan_hosts_reached ()
{
  return scan_restrictions.max_scan_hosts_reached;
}

/**
 * @brief Set max_scan_hosts_reached to TRUE.
 */
void
set_max_scan_hosts_reached ()
{
  scan_restrictions.max_scan_hosts_reached = TRUE;
}

/**
 * @brief Get number of identified alive hosts.
 *
 * @return Number of identified alive hosts.
 * */
static int
get_alive_hosts_count ()
{
  return scan_restrictions.alive_hosts_count;
}

/**
 * @brief Get set number of maximum alive hosts to be scanned.
 *
 * @return Number of maximum alive hosts to be scanned.
 */
static int
get_max_scan_hosts ()
{
  return scan_restrictions.max_scan_hosts;
}

/**
 * @brief Increment the number of alive hosts by one.
 */
static void
inc_alive_hosts_count ()
{
  scan_restrictions.alive_hosts_count++;
  return;
}

/**
 * @brief Send Message about not vuln scanned alive hosts to ospd-openvas.
 *
 * @param num_not_scanned Number of alive hosts which were not vuln scanned.
 * @return 0 on success, else Error.
 */
static int
send_limit_msg (int num_not_scanned_hosts)
{
  int err;
  int dbid;
  kb_t main_kb = NULL;

  err = 0;

  if (num_not_scanned_hosts < 0)
    return -1;

  dbid = atoi (prefs_get ("ov_maindbid"));
  if ((main_kb = kb_direct_conn (prefs_get ("db_address"), dbid)))
    {
      char buf[256];
      g_snprintf (buf, 256,
                  "ERRMSG||| ||| ||| |||Maximum number of allowed scans "
                  "reached. There may still be alive hosts available which are "
                  "not scanned. Number of alive hosts not scanned: [%d]",
                  num_not_scanned_hosts);
      if (kb_item_push_str (main_kb, "internal/results", buf) != 0)
        {
          g_warning ("%s: kb_item_push_str() failed to push "
                     "error message.",
                     __func__);
          err = -2;
        }
      kb_lnk_reset (main_kb);
    }
  else
    {
      g_warning ("%s: Boreas was unable to connect to the Redis db.Info about "
                 "number of alive hosts could not be sent.",
                 __func__);
      err = -3;
    }

  return err;
}

/**
 * @brief Get new host from alive detection scanner.
 *
 * Check if an alive host was found by the alive detection scanner. If an alive
 * host is found it is packed into a gvm_host_t and returned. If no host was
 * found or an error occurred NULL is returned. If alive detection finished
 * scanning all hosts, NULL is returned and the status flag
 * alive_detection_finished is set to TRUE.
 *
 * @param alive_hosts_kb  Redis connection for accessing the queue on which the
 * alive detection scanner puts found hosts.
 * @param alive_deteciton_finished  Status of alive detection process.
 * @return  If valid alive host is found return a gvm_host_t. If alive scanner
 * finished NULL is returened and alive_deteciton_finished set. On error or if
 * no host was found return NULL.
 */
gvm_host_t *
get_host_from_queue (kb_t alive_hosts_kb, gboolean *alive_deteciton_finished)
{
  /* redis connection not established yet */
  if (!alive_hosts_kb)
    {
      g_debug ("%s: connection to redis is not valid", __func__);
      return NULL;
    }

  /* string representation of an ip address or ALIVE_DETECTION_FINISHED */
  gchar *host_str = NULL;
  /* complete host to be returned */
  gvm_host_t *host = NULL;

  /* try to get item from db, string needs to be freed, NULL on empty or
   * error
   */
  host_str = kb_item_pop_str (alive_hosts_kb, (ALIVE_DETECTION_QUEUE));
  if (!host_str)
    {
      return NULL;
    }
  /* got some string from redis queue */
  else
    {
      /* check for finish signal/string */
      if (g_strcmp0 (host_str, ALIVE_DETECTION_FINISHED) == 0)
        {
          /* Send Error message if max_scan_hosts was reached. */
          if (max_scan_hosts_reached ())
            {
              int num_not_scanned_hosts;

              num_not_scanned_hosts =
                get_alive_hosts_count () - get_max_scan_hosts ();
              send_limit_msg (num_not_scanned_hosts);
            }
          g_debug ("%s: Boreas already finished scanning and we reached the "
                   "end of the Queue of alive hosts.",
                   __func__);
          g_free (host_str);
          *alive_deteciton_finished = TRUE;
          return NULL;
        }
      /* probably got host */
      else
        {
          host = gvm_host_from_str (host_str);
          g_free (host_str);

          if (!host)
            {
              g_warning ("%s: Could not transform IP string \"%s\" into "
                         "internal representation.",
                         __func__, host_str);
              return NULL;
            }
          else
            {
              return host;
            }
        }
    }
}

/**
 * @brief Put host value string on queue of hosts to be considered as alive.
 *
 * @param kb KB to use.
 * @param addr_str IP addr in str representation to put on queue.
 */
static void
put_host_on_queue (kb_t kb, char *addr_str)
{
  /* Print host on command line if no kb is available. No kb available could
   * mean that boreas is used as commandline tool.*/
  if (NULL == kb)
    {
      g_printf ("%s\n", addr_str);
      return;
    }

  if (kb_item_push_str (kb, ALIVE_DETECTION_QUEUE, addr_str) != 0)
    g_debug ("%s: kb_item_push_str() failed. Could not push \"%s\" on queue of "
             "hosts to be considered as alive.",
             __func__, addr_str);
}

/**
 * @brief Put finish signal on alive detection queue.
 *
 * If the finish signal (a string) was already put on the queue it is not put on
 * it again.
 *
 * @param error  Set to 0 on success. Is set to -1 if finish signal was already
 * put on queue. Set to -2 if function was no able to push finish string on
 * queue.
 */
void
put_finish_signal_on_queue (void *error)
{
  static gboolean fin_msg_already_on_queue = FALSE;
  boreas_error_t error_out;
  int kb_item_push_str_err;

  error_out = NO_ERROR;
  if (fin_msg_already_on_queue)
    {
      g_debug ("%s: Finish signal was already put on queue.", __func__);
      error_out = -1;
    }
  else
    {
      kb_t main_kb;
      int scandb_id;

      scandb_id = atoi (prefs_get ("ov_maindbid"));
      main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id);

      kb_item_push_str_err = kb_item_push_str (main_kb, ALIVE_DETECTION_QUEUE,
                                               ALIVE_DETECTION_FINISHED);
      if (kb_item_push_str_err)
        {
          g_debug ("%s: Could not push the Boreas finish signal on the alive "
                   "detection Queue.",
                   __func__);
          error_out = -2;
        }
      else
        fin_msg_already_on_queue = TRUE;

      if ((kb_lnk_reset (main_kb)) != 0)
        {
          g_warning ("%s: error in kb_lnk_reset()", __func__);
          error_out = -3;
        }
    }
  /* Set error. */
  *(boreas_error_t *) error = error_out;
}

/**
 * @brief Init scan restrictions.
 *
 * @param scanner Pointer to scanner struct.
 * @param max_scan_hosts  Maximum number of hosts allowed to scan. 0 equals no
 * scan limit.
 */
void
init_scan_restrictions (struct scanner *scanner, int max_scan_hosts)
{
  scan_restrictions.alive_hosts_count = 0;
  scan_restrictions.max_scan_hosts_reached = FALSE;
  scan_restrictions.max_scan_hosts = max_scan_hosts;
  scanner->scan_restrictions = &scan_restrictions;
  return;
}

/**
 * @brief Handle restrictions imposed by max_scan_hosts.
 *
 * Put host address string on alive detection queue if max_scan_hosts was not
 * reached already. If max_scan_hosts was reached only count alive hosts and
 * don't put them on the queue. Put finish signal on queue if max_scan_hosts is
 * reached.
 *
 * @param scanner Scanner struct.
 * @param add_str Host address string to put on queue.
 */
void
handle_scan_restrictions (struct scanner *scanner, gchar *addr_str)
{
  inc_alive_hosts_count ();
  /* Put alive hosts on queue as long as max_scan_hosts not reached. */
  if (!max_scan_hosts_reached ())
    put_host_on_queue (scanner->main_kb, addr_str);

  /* Set max_scan_hosts_reached if not already set and max_scan_hosts was
   * reached. */
  if (!max_scan_hosts_reached ()
      && (get_alive_hosts_count () == get_max_scan_hosts ()))
    {
      set_max_scan_hosts_reached ();
    }
}

/**
 * @brief Send the number of dead hosts to ospd-openvas.
 *
 * This information is needed for the calculation of the progress bar for gsa in
 * ospd-openvas. The number of dead hosts sent to ospd-openvas may not
 * necessarily reflect the actual number of dead hosts in the target list.
 *
 * @param hosts_data  Includes all data which is needed for calculating the
 * number of dead hosts.
 *
 * @return number of dead hosts, or -1 in case of an error.
 */
void
send_dead_hosts_to_ospd_openvas (int count_dead_hosts)
{
  kb_t main_kb;
  int maindbid;
  char dead_host_msg_to_ospd_openvas[2048];

  maindbid = atoi (prefs_get ("ov_maindbid"));
  main_kb = kb_direct_conn (prefs_get ("db_address"), maindbid);

  if (!main_kb)
    {
      g_debug ("%s: Could not connect to main_kb for sending dead hosts to "
               "ospd-openvas.",
               __func__);
    }

  snprintf (dead_host_msg_to_ospd_openvas,
            sizeof (dead_host_msg_to_ospd_openvas), "DEADHOST||| ||| ||| |||%d",
            count_dead_hosts);
  kb_item_push_str (main_kb, "internal/results", dead_host_msg_to_ospd_openvas);

  kb_lnk_reset (main_kb);
}

/**
 * @brief Get the openvas scan id of the current task.
 *
 * @param db_address  Address of the Redis db.
 * @param db_id ID of the scan main db.
 *
 * @return Scan id of current task or NULL on error.
 */
gchar *
get_openvas_scan_id (const gchar *db_address, int db_id)
{
  kb_t main_kb = NULL;
  gchar *scan_id;
  if ((main_kb = kb_direct_conn (db_address, db_id)))
    {
      scan_id = kb_item_get_str (main_kb, ("internal/scanid"));
      kb_lnk_reset (main_kb);
      return scan_id;
    }
  return NULL;
}

/**
 * @brief Get the bitflag which describes the methods to use for alive
 * deteciton.
 *
 * @param[out]  alive_test  Bitflag of all specified alive detection methods.
 *
 * @return 0 on success, boreas_error_t on failure.
 */
boreas_error_t
get_alive_test_methods (alive_test_t *alive_test)
{
  boreas_error_t error = NO_ERROR;
  const gchar *alive_test_pref_as_str;

  alive_test_pref_as_str = prefs_get ("ALIVE_TEST");
  if (alive_test_pref_as_str == NULL)
    {
      g_warning ("%s: No valid alive_test specified.", __func__);
      error = BOREAS_NO_VALID_ALIVE_TEST_SPECIFIED;
    }
  else
    {
      *alive_test = atoi (alive_test_pref_as_str);
    }
  return error;
}
