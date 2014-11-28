/* openvas-libraries/nasl
 * $Id$
 * Description: Implementation of an API for SNMP used by NASL scripts.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <assert.h>
#include "openvas_logging.h"
#include "nasl_lex_ctxt.h"

#ifdef HAVE_NETSNMP
static char *
snmpv1_get (const char *peername, const char *community, const char *oid_str)
{
  struct snmp_session session, *ss;
  struct snmp_pdu *query, *response;
  oid oid_buf[MAX_OID_LEN];
  size_t oid_size = MAX_OID_LEN;
  int status;

  assert (peername);
  assert (community);
  assert (oid_str);

  snmp_sess_init (&session);
  session.version = SNMP_VERSION_1;
  session.peername = (char *) peername;
  session.community = (u_char *) community;
  session.community_len = strlen (community);

  ss = snmp_open (&session);
  if (!ss)
    {
      char *errstr = NULL;

      snmp_error (&session, &status, &status, &errstr);
      log_legacy_write ("snmpv1_get: %s", errstr);
      g_free (errstr);
      return NULL;
    }
  query = snmp_pdu_create (SNMP_MSG_GET);
  read_objid(oid_str, oid_buf, &oid_size);
  snmp_add_null_var (query, oid_buf, oid_size);
  status = snmp_synch_response (ss, query, &response);
  if (status != STAT_SUCCESS)
    {
      char *errstr = NULL;

      snmp_error (ss, &status, &status, &errstr);
      snmp_close (ss);
      log_legacy_write ("snmpv1_get: %s", errstr);
      g_free (errstr);
      return NULL;
    }
  snmp_close (ss);

  if (response->errstat == SNMP_ERR_NOERROR)
    {
      struct variable_list *vars = response->variables;
      size_t res_len = 0, buf_len = 0;
      char *result = NULL;

      netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                             NETSNMP_DS_LIB_QUICK_PRINT, 1);
      sprint_realloc_value ((u_char **) &result, &buf_len, &res_len, 1,
                            vars->name, vars->name_length, vars);
      snmp_free_pdu (response);
      return result;
    }
  log_legacy_write ("snmpv1_get: %s", snmp_errstring (response->errstat));
  snmp_free_pdu (response);
  return NULL;
}

tree_cell *
nasl_snmpv1_get (lex_ctxt *lexic)
{
  const char *peername, *community, *oid_str;
  char *result = NULL;

  peername = get_str_var_by_name (lexic, "peername");
  community = get_str_var_by_name (lexic, "community");
  oid_str = get_str_var_by_name (lexic, "oid");
  if (!peername || !community || !oid_str)
    {
      log_legacy_write ("snmpv1_get: Missing function arguments");
      return NULL;
    }

  result = snmpv1_get (peername, community, oid_str);
  if (result)
    {
      tree_cell *retc = alloc_typed_cell (CONST_STR);

      retc->x.str_val = result;
      retc->size = strlen (result);
      return retc;
    }
  return NULL;
}

#endif /* HAVE_NETSNMP */
