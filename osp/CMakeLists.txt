# openvas-libraries/osp
# $Id$
# Description: Top-level cmake control for the OSP library.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Library

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -Wextra -fPIC")

set (FILES osp.c)

set (HEADERS osp.h)

include_directories (${GLIB_INCLUDE_DIRS})

if (BUILD_STATIC)
  add_library (openvas_osp_static STATIC ${FILES})
  set_target_properties (openvas_osp_static PROPERTIES OUTPUT_NAME "openvas_osp")
  set_target_properties (openvas_osp_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_osp_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (openvas_osp_shared SHARED ${FILES})
  set_target_properties (openvas_osp_shared PROPERTIES OUTPUT_NAME "openvas_osp")
  set_target_properties (openvas_osp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_osp_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
  set_target_properties (openvas_osp_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (openvas_osp_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (openvas_osp_shared openvas_base_shared openvas_misc_shared openvas_omp_shared ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)

## Install
if (BUILD_STATIC)
  install (TARGETS openvas_osp_static
           RUNTIME DESTINATION ${BINDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/osp")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS openvas_osp_shared
           RUNTIME DESTINATION ${BINDIR}
           LIBRARY DESTINATION ${LIBDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/osp")
endif (BUILD_SHARED)

## End
