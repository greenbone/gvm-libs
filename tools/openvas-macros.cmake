# OpenVAS
# $Id$
# Description: Top-level cmake control for the Manager.
#
# Authors:
# Matthew Mundell <matt@mundell.ukfsn.org>
# Felix Wolfsteller <felix.wolfsteller@intevation.de>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Retrieve svn revision (at configure time)
#  Not using Subversion_WC_INFO, as it would have to connect to the repo

find_program (SVN_EXECUTABLE svn DOC "subversion command line client")

macro (get_svn_revision dir variable)
  execute_process (COMMAND ${SVN_EXECUTABLE} info ${dir}
                   OUTPUT_VARIABLE ${variable}
                   OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REGEX REPLACE "^(.*\n)?Revision: ([^\n]+).*"
          "\\2" ${variable} "${${variable}}")
endmacro (get_svn_revision)

if (NOT PREPARE_RELEASE)
  if (SVN_EXECUTABLE)
    get_svn_revision (. ProjectRevision)
    set (SVN_REVISION ".SVN.r${ProjectRevision}")
  else (SVN_EXECUTABLE)
    set (SVN_REVISION ".SVN")
  endif (SVN_EXECUTABLE)
endif (NOT PREPARE_RELEASE)

macro (openvas_need_lib library)
  set (tmp_lib_found "")
  message (STATUS "Looking for ${library}...")
  find_library (tmp_lib_found ${library})
  message (STATUS "Looking for ${library}... ${tmp_lib_found}")
  if (NOT tmp_lib_found)
    message (FATAL_ERROR "The ${library} library is required.")
  endif (NOT tmp_lib_found)
macro (openvas_need_lib)
