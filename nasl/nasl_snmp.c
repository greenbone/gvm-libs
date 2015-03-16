/* openvas-libraries/nasl
 * $Id$
 * Description: Implementation of an API for SNMP used by NASL scripts.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014-2015 Greenbone Networks GmbH
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

#ifdef HAVE_NETSNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <assert.h>
#include "openvas_logging.h"
#include "nasl_lex_ctxt.h"
#include "plugutils.h"

/*
 * @brief SNMP Get query value.
 *
 * param[in]    session     SNMP session.
 * param[in]    oid_str     OID string.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmp_get (struct snmp_session *session, const char *oid_str, char **result)
{
  struct snmp_session *ss;
  struct snmp_pdu *query, *response;
  oid oid_buf[MAX_OID_LEN];
  size_t oid_size = MAX_OID_LEN;
  int status;

  ss = snmp_open (session);
  if (!ss)
    {
      snmp_error (session, &status, &status, result);
      return -1;
    }
  query = snmp_pdu_create (SNMP_MSG_GET);
  read_objid (oid_str, oid_buf, &oid_size);
  snmp_add_null_var (query, oid_buf, oid_size);
  status = snmp_synch_response (ss, query, &response);
  if (status != STAT_SUCCESS)
    {
      snmp_error (ss, &status, &status, result);
      snmp_close (ss);
      return -1;
    }
  snmp_close (ss);

  if (response->errstat == SNMP_ERR_NOERROR)
    {
      struct variable_list *vars = response->variables;
      size_t res_len = 0, buf_len = 0;

      netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                             NETSNMP_DS_LIB_QUICK_PRINT, 1);
      sprint_realloc_value ((u_char **) result, &buf_len, &res_len, 1,
                            vars->name, vars->name_length, vars);
      snmp_free_pdu (response);
      return 0;
    }
  *result = g_strdup (snmp_errstring (response->errstat));
  snmp_free_pdu (response);
  return -1;
}

/*
 * @brief SNMPv3 Get query value.
 *
 * param[in]    peername    Target host in [protocol:]address[:port] format.
 * param[in]    username    Username value.
 * param[in]    password    Password value.
 * param[in]    oid_str     OID of value to get.
 * param[in]    algorithm   md5 or sha1.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv3_get (const char *peername, const char *username, const char *password,
            const char *oid_str, int algorithm, char **result)
{
  struct snmp_session session;

  assert (peername);
  assert (username);
  assert (password);
  assert (oid_str);
  assert (algorithm == 0 || algorithm == 1);

  init_snmp ("openvas");
  snmp_sess_init (&session);
  session.version = SNMP_VERSION_3;
  session.peername = (char *) peername;
  session.securityName = (char *) username;
  session.securityNameLen = strlen (session.securityName);

  session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
  if (algorithm == 0)
    {
      session.securityAuthProto = usmHMACMD5AuthProtocol;
      session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
    }
  else
    {
      session.securityAuthProto = usmHMACSHA1AuthProtocol;
      session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
    }
  session.securityAuthKeyLen = USM_AUTH_KU_LEN;
  if (generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                  (u_char *) password, strlen (password),
                  session.securityAuthKey, &session.securityAuthKeyLen)
      != SNMPERR_SUCCESS)
   {
     log_legacy_write ("generate_Ku: Error");
     return -1;
   }

  return snmp_get (&session, oid_str, result);
}

/*
 * @brief SNMPv1 Get query value.
 *
 * param[in]    peername    Target host in [protocol:]address[:port] format.
 * param[in]    community   SNMP community string.
 * param[in]    oid_str     OID string of value to get.
 * param[out]   result      Result of query.
 *
 * @return 0 if success and result value, -1 otherwise.
 */
static int
snmpv1_get (const char *peername, const char *community, const char *oid_str,
            char **result)
{
  struct snmp_session session;

  assert (peername);
  assert (community);
  assert (oid_str);

  snmp_sess_init (&session);
  session.version = SNMP_VERSION_1;
  session.peername = (char *) peername;
  session.community = (u_char *) community;
  session.community_len = strlen (community);

  return snmp_get (&session, oid_str, result);
}

/*
 * @brief Check that protocol value is valid.
 *
 * param[in]    proto   Protocol string.
 *
 * @return 1 if proto is udp, udp6, tcp or tcp6. 0 otherwise.
 */
static int
proto_is_valid (const char *proto)
{
  if (strcmp (proto, "tcp") && strcmp (proto, "udp") && strcmp (proto, "tcp6")
      && strcmp (proto, "udp6"))
    return 0;
  return 1;
}

/*
 * @brief Create a NASL array from a snmp result.
 *
 * param[in]    ret     Return value.
 * param[in]    result  Result string.
 *
 * @return NASL array.
 */
static tree_cell *
array_from_snmp_result (int ret, char *result)
{
  anon_nasl_var v;

  assert (result);
  tree_cell *retc = alloc_typed_cell (DYN_ARRAY);
  retc->x.ref_val = g_malloc0 (sizeof (nasl_array));
  /* Return code */
  memset (&v, 0, sizeof (v));
  v.var_type = VAR2_INT;
  v.v.v_int = ret;
  add_var_to_list (retc->x.ref_val, 0, &v);
  /* Return value */
  memset (&v, 0, sizeof v);
  v.var_type = VAR2_STRING;
  v.v.v_str.s_val = (unsigned char *) result;
  v.v.v_str.s_siz = strlen (result);
  add_var_to_list (retc->x.ref_val, 1, &v);

  return retc;
}

tree_cell *
nasl_snmpv1_get (lex_ctxt *lexic)
{
  const char *proto, *community, *oid_str;
  char *result = NULL, peername[2048];
  int port, ret;

  port = get_int_var_by_name (lexic, "port", -1);
  proto = get_str_var_by_name (lexic, "protocol");
  community = get_str_var_by_name (lexic, "community");
  oid_str = get_str_var_by_name (lexic, "oid");
  if (!proto || !community || !oid_str)
    return array_from_snmp_result (-2, "Missing function argument");
  if (port < 0 || port > 65535)
    return array_from_snmp_result (-2, "Invalid port value");
  if (!proto_is_valid (proto))
    return array_from_snmp_result (-2, "Invalid protocol value");

  g_snprintf (peername, sizeof (peername), "%s:%s:%d", proto,
              plug_get_host_ip_str (lexic->script_infos), port);
  ret = snmpv1_get (peername, community, oid_str, &result);
  return array_from_snmp_result (ret, result);
}

tree_cell *
nasl_snmpv3_get (lex_ctxt *lexic)
{
  const char *proto, *username, *password, *algorithm, *oid_str;
  char *result = NULL, peername[2048];
  int port, ret;

  port = get_int_var_by_name (lexic, "port", -1);
  proto = get_str_var_by_name (lexic, "protocol");
  username = get_str_var_by_name (lexic, "username");
  password = get_str_var_by_name (lexic, "password");
  oid_str = get_str_var_by_name (lexic, "oid");
  algorithm = get_str_var_by_name (lexic, "algorithm");
  if (!proto || !username || !password || !oid_str || !algorithm)
    return array_from_snmp_result (-2, "Missing function argument");
  if (port < 0 || port > 65535)
    return array_from_snmp_result (-2, "Invalid port value");
  if (!proto_is_valid (proto))
    return array_from_snmp_result (-2, "Invalid protocol value");
  g_snprintf (peername, sizeof (peername), "%s:%s:%d", proto,
              plug_get_host_ip_str (lexic->script_infos), port);
  if (!strcasecmp (algorithm, "md5"))
    ret = snmpv3_get (peername, username, password, oid_str, 0, &result);
  else if (!strcasecmp (algorithm, "sha1"))
    ret = snmpv3_get (peername, username, password, oid_str, 1, &result);
  else
    return array_from_snmp_result
            (-2, "snmpv3_get: algorithm should be md5 or sha1");
  return array_from_snmp_result (ret, result);
}

#endif /* HAVE_NETSNMP */
