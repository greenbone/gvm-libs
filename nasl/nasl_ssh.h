/* openvas-libraries/nasl
 * $Id$
 * Description: API (structs and protos) for SSH functions used by NASL scripts
 *
 * Authors:
 * Michael Wiegand <michael.wiegand@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation.
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

/**
 * @file nasl_ssh.h
 * @brief Protos and data structures for SSH functions used by NASL scripts
 *
 * This file contains the protos for \ref nasl_ssh.c
 */

#ifdef HAVE_LIBSSH
#ifndef NASL_SSH_H
#define NASL_SSH_H

tree_cell *nasl_ssh_exec (lex_ctxt *);
#endif
#endif
