/* OpenVAS
 *
 * $Id$
 * Description: NASL API implementation for SMB support
 *
 * Authors:
 * Chandrashekhar B <bchandra@secpod.com>
 *
 * Copyright:
 * Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file nasl_smb.c
 *
 * @brief API for NASL built-in SMB access focussing effective file rights
 *
 * Provides SMB API as built-in functions to NASL via calling
 * corresponding functions of a appropriate library.
 * The focus is on effective files rights which can't be retrieved
 * via WMI.
 */

/**
 * @todo Check for memleak and document reference counting in tree cells.
 *       In some cases, after a tree_cell (typically retc) has been allocated
 *       with alloc_tree_cell, it is not later freed or deref_tree_cell'ed. It
 *       has to evaluated if that is okay or leads to memory leaks.
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "nasl_smb.h"
#include "openvas_smb_interface.h"
#include "../misc/plugutils.h"
#include "../misc/openvas_logging.h"

#define IMPORT(var) char *var = get_str_var_by_name(lexic, #var)

/**
 * @brief Get a version string of the SMB implementation.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case no implementation is present.
 *         Else a tree_cell with the version as string.
 */
tree_cell *
nasl_smb_versioninfo (lex_ctxt * lexic)
{
  char *version = smb_versioninfo ();
  tree_cell *retc = alloc_tree_cell (0, NULL);

  if (!version)
    {
      return NULL;
    }

  retc->type = CONST_DATA;
  retc->x.str_val = strdup (version);
  retc->size = strlen (version);

  return retc;
}

/**
 * @brief Connect to SMB service and return a handle for it.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case the connection could not be established.
 *         Else a tree_cell with the handle.
 *
 * Retrieves local variables "host", "username", "password" and "share"
 * from the lexical context, performs and connects to this given
 * SMB service returning a handle for the service as integer.
 */
tree_cell *
nasl_smb_connect (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  struct in6_addr *host = plug_get_host_ip (script_infos);
  char *ip;
  char *username = get_str_var_by_name (lexic, "username");
  char *password = get_str_var_by_name (lexic, "password");
  char *share = get_str_var_by_name (lexic, "share");

  tree_cell *retc;
  SMB_HANDLE handle;
  int value;

  if ((host == NULL) || (username == NULL) || (password == NULL)
      || (share == NULL))
    {
      log_legacy_write ("nasl_smb_connect: Invalid input arguments\n");
      return NULL;
    }

  ip = addr6_as_str (host);
  if ((strlen (password) == 0) || (strlen (username) == 0)
      || (strlen (ip) == 0) || (strlen (share) == 0))
    {
      log_legacy_write ("nasl_smb_connect: Invalid input arguments\n");
      g_free (ip);
      return NULL;
    }

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_INT;
  value = smb_connect (ip, share, username, password, &handle);
  g_free (ip);

  if (value == -1)
    {
      log_legacy_write ("nasl_smb_connect: SMB Connect failed\n");
      return NULL;
    }

  retc->x.i_val = (int) handle;
  return retc;
}

/**
 * @brief Close SMB service handle.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of a serious problem. Else returns a
 *         treecell with integer == 1.
 *
 * Retrieves local variable "smb_handle" from the lexical context
 * and closes the respective handle.
 */
tree_cell *
nasl_smb_close (lex_ctxt * lexic)
{
  SMB_HANDLE handle =
    (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  int ret;
  tree_cell *retc;

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_INT;

  ret = smb_close (handle);
  if (ret == 0)
    {
      retc->x.i_val = 1;
      return retc;
    }
  else
    return NULL;
}

/**
 * @brief Obtain Security Descriptor in SDDL format
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with SDDL string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_SDDL (lex_ctxt * lexic)
{
  SMB_HANDLE handle =
    (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      log_legacy_write ("smb_file_SDDL failed: Invalid filename\n");
      return NULL;
    }

  if (!handle)
    {
      log_legacy_write ("smb_file_SDDL failed: Invalid smb_handle\n");
      return NULL;
    }

  tree_cell *retc;
  char *buffer = NULL;

  buffer = smb_file_SDDL (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}

/**
 * @brief Obtain File Owner SID
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with Owner SID string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_owner_sid (lex_ctxt * lexic)
{
  SMB_HANDLE handle =
    (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      log_legacy_write ("smb_file_owner_sid failed: Invalid filename\n");
      return NULL;
    }

  if (!handle)
    {
      log_legacy_write ("smb_file_owner_sid failed: Invalid smb_handle\n");
      return NULL;
    }

  tree_cell *retc;
  char *buffer;

  buffer = smb_file_OwnerSID (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}

/**
 * @brief Obtain File Group SID
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with Group SID string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_group_sid (lex_ctxt * lexic)
{
  SMB_HANDLE handle =
    (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      log_legacy_write ("smb_file_group_sid failed: Invalid filename\n");
      return NULL;
    }

  if (!handle)
    {
      log_legacy_write ("smb_file_group_sid failed: Invalid smb_handle\n");
      return NULL;
    }

  tree_cell *retc;
  char *buffer;

  buffer = smb_file_GroupSID (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}


/**
 * @brief Obtain File Trustee SID with Access Mask
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL in case of problem. Else returns a
 *         treecell with Trustee SID and Access Mask string
 *
 * Retrieves local variable "smb_handle" and "filename" from the lexical context
 * and perform file rights query.
 */
tree_cell *
nasl_smb_file_trustee_rights (lex_ctxt * lexic)
{
  SMB_HANDLE handle =
    (SMB_HANDLE) get_int_var_by_name (lexic, "smb_handle", 0);
  char *filename = get_str_var_by_name (lexic, "filename");

  if (!filename)
    {
      log_legacy_write ("smb_file_trustee_rights failed: Invalid filename\n");
      return NULL;
    }

  if (!handle)
    {
      log_legacy_write ("smb_file_trustee_rights failed: Invalid smb_handle\n");
      return NULL;
    }

  tree_cell *retc;
  char *buffer;

  buffer = smb_file_TrusteeRights (handle, filename);

  if (buffer == NULL)
    return NULL;

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = strlen (buffer);
  retc->x.str_val = strdup (buffer);
  return retc;
}


/**
 * @brief Execute the command in windows
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return NULL if the query fails.
 *  Else a tree_cell with the command execution result.
 *
 * Retrieves local variables "cmd" from the lexical
 * context, performs the windows command execution operation
 * returning the result.
 */

tree_cell *
nasl_win_cmd_exec (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  struct in6_addr *host = plug_get_host_ip (script_infos);
  char *ip;
  char *res = NULL;
  char *argv[5];

  IMPORT (username);
  IMPORT (password);
  IMPORT (cmd);

  int argc = 5, value;
  char *argv1 = "winexe";
  char *argv2 = "-U";

  if ((host == NULL) || (username == NULL) || (password == NULL) || (cmd == NULL))
    {
      log_legacy_write ("win_cmd_exec: Invalid input arguments\n");
      return NULL;
    }

  ip = addr6_as_str (host);
  if ((strlen (password) == 0) || (strlen (username) == 0)
      || strlen (ip) == 0)
    {
      log_legacy_write ("win_cmd_exec: Invalid input arguments\n");
      g_free(ip);
      return NULL;
    }

  argv[0] = (char *) g_malloc0 (strlen (argv1) + 1);
  argv[1] = (char *) g_malloc0 (strlen (argv2) + 1);
  argv[2] = (char *) g_malloc0 (strlen (username) + strlen (password) + 1 + 1);
  argv[3] = (char *) g_malloc0 (strlen (ip) + 2 + 1);
  argv[4] = (char *) g_malloc0 (strlen (cmd) + 1);

  // Construct the WinCMD query
  strcpy (argv[0], argv1);
  strcpy (argv[1], "-U");
  strcpy (argv[2], username);
  strcat (argv[2], "%");
  strcat (argv[2], password);
  strcpy (argv[3], "//");
  strcat (argv[3], ip);
  strcpy (argv[4], cmd);

  tree_cell *retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->x.str_val = NULL;
  retc->size = 0;

  value = wincmd (argc, argv, &res);
  if (value == -1)
    {
      log_legacy_write ("win_cmd_exec: WinCMD Connect failed\n");
      g_free(ip);
      return NULL;
    }

  retc->x.str_val = strdup (res);
  retc->size = strlen (res);
  g_free(ip);
  return retc;
}
