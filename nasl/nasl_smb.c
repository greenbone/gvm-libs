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
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * (or any later version), as published by the Free Software Foundation.
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

#include <stdio.h>
#include <string.h>

#include "nasl_smb.h"
#include "openvas_smb_interface.h"

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
  char * version = smb_versioninfo();
  tree_cell *retc = alloc_tree_cell (0, NULL);

  if (!retc) return NULL;

  retc->type = CONST_DATA;
  retc->x.str_val = strdup(version);
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
tree_cell *nasl_smb_connect(lex_ctxt* lexic)
{
  char *host = get_str_local_var_by_name(lexic, "host");
  char *username = get_str_local_var_by_name(lexic, "username");
  char *password = get_str_local_var_by_name(lexic, "password");
  char *share = get_str_local_var_by_name(lexic, "share");

  tree_cell * retc;
  SMB_HANDLE handle;
  int value;

  if((host == NULL) || (username == NULL) ||
     (password == NULL) || (share == NULL)) {
    fprintf(stderr, "nasl_smb_connect: Invalid input arguments\n");
    return NULL;
  }

  if((strlen(password) == 0) || (strlen(username) == 0) ||
      (strlen(host) == 0) || (strlen(share) == 0)) {
    fprintf(stderr, "nasl_smb_connect: Invalid input arguments\n");
    return NULL;
  }

  retc = alloc_tree_cell(0,NULL);
  if(!retc) return NULL;

  retc->type = CONST_INT;
  value = smb_connect(host, share, username, password, &handle);

  if(value == -1)
  {
    fprintf(stderr, "nasl_smb_connect: SMB Connect failed\n");
    return NULL;
  }

  retc->x.i_val = (int)handle;
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
tree_cell *nasl_smb_close(lex_ctxt* lexic)
{
  SMB_HANDLE handle= (SMB_HANDLE) get_int_local_var_by_name(lexic, "smb_handle", 0);
  int ret;
  tree_cell *retc;

  retc = alloc_tree_cell(0,NULL);
  if(!retc) return NULL;

  retc->type = CONST_INT;

  ret = smb_close(handle);
  if(ret == 0) {
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
tree_cell *nasl_smb_file_SDDL(lex_ctxt* lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_local_var_by_name(lexic, "smb_handle", 0);
  char *filename = get_str_local_var_by_name(lexic, "filename");

  if(!filename)
  {
    fprintf(stderr, "smb_file_SDDL failed: Invalid filename\n");
    return NULL;
  }

  if(!handle)
  {
    fprintf(stderr, "smb_file_SDDL failed: Invalid smb_handle\n");
    return NULL;
  }

  tree_cell * retc;
  char * buffer = NULL;

  buffer = smb_file_SDDL(handle, filename);

  if(buffer == NULL) return NULL;

  retc = alloc_tree_cell(0,NULL);
  if(retc)
  {
    retc->type = CONST_DATA;
    retc->size = strlen(buffer);
    retc->x.str_val = strdup(buffer);
  }
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
tree_cell *nasl_smb_file_owner_sid(lex_ctxt* lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_local_var_by_name(lexic, "smb_handle", 0);
  char *filename = get_str_local_var_by_name(lexic, "filename");

  if(!filename)
  {
    fprintf(stderr, "smb_file_owner_sid failed: Invalid filename\n");
    return NULL;
  }

  if(!handle)
  {
    fprintf(stderr, "smb_file_owner_sid failed: Invalid smb_handle\n");
    return NULL;
  }

  tree_cell * retc;
  char * buffer;

  buffer = smb_file_OwnerSID(handle, filename);

  if(buffer == NULL) return NULL;

  retc = alloc_tree_cell(0,NULL);
  if(retc)
  {
     retc->type = CONST_DATA;
     retc->size = strlen(buffer);
     retc->x.str_val = strdup(buffer);
  }
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
tree_cell *nasl_smb_file_group_sid(lex_ctxt* lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_local_var_by_name(lexic, "smb_handle", 0);
  char *filename = get_str_local_var_by_name(lexic, "filename");

  if(!filename)
  {
    fprintf(stderr, "smb_file_group_sid failed: Invalid filename\n");
    return NULL;
  }

  if(!handle)
  {
    fprintf(stderr, "smb_file_group_sid failed: Invalid smb_handle\n");
    return NULL;
  }

  tree_cell * retc;
  char * buffer;

  buffer = smb_file_GroupSID(handle, filename);

  if(buffer == NULL) return NULL;

  retc = alloc_tree_cell(0,NULL);
  if(retc)
  {
    retc->type = CONST_DATA;
    retc->size = strlen(buffer);
    retc->x.str_val = strdup(buffer);
  }
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
tree_cell *nasl_smb_file_trustee_rights(lex_ctxt* lexic)
{
  SMB_HANDLE handle = (SMB_HANDLE) get_int_local_var_by_name(lexic, "smb_handle", 0);
  char *filename = get_str_local_var_by_name(lexic, "filename");

  if(!filename)
  {
    fprintf(stderr, "smb_file_trustee_rights failed: Invalid filename\n");
    return NULL;
  }

  if(!handle)
  {
    fprintf(stderr, "smb_file_trustee_rights failed: Invalid smb_handle\n");
    return NULL;
  }

  tree_cell * retc;
  char * buffer;

  buffer = smb_file_TrusteeRights(handle, filename);

  if(buffer == NULL) return NULL;

  retc = alloc_tree_cell(0,NULL);
  if(retc)
  {
    retc->type = CONST_DATA;
    retc->size = strlen(buffer);
    retc->x.str_val = strdup(buffer);
  }
  return retc;
}
