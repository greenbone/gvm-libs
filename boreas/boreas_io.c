/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
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

#include "alivedetection.h"

/**
 * @brief Put host value string on queue of hosts to be considered as alive.
 *
 * @param kb KB to use.
 * @param addr_str IP addr in str representation to put on queue.
 */
void
put_host_on_queue (kb_t kb, char *addr_str)
{
  if (kb_item_push_str (kb, ALIVE_DETECTION_QUEUE, addr_str) != 0)
    g_debug ("%s: kb_item_push_str() failed. Could not push \"%s\" on queue of "
             "hosts to be considered as alive.",
             __func__, addr_str);
}

/**
 * @brief Get the openvas scan id of the curent task.
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
