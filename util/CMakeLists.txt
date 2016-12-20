# gvm-libs/util
# $Id$
# Description: cmake control for the util library.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

# for compressutils.c we need zlib
pkg_check_modules (ZLIB REQUIRED zlib)

# for fileutils.c we need giolib
pkg_check_modules (GIO REQUIRED gio-2.0)

include_directories (${GLIB_INCLUDE_DIRS})

set (FILES compressutils.c fileutils.c)

set (HEADERS compressutils.h fileutils.h)

if (BUILD_STATIC)
  add_library (gvm_util_static STATIC ${FILES})
  set_target_properties (gvm_util_static PROPERTIES OUTPUT_NAME "gvm_util")
  set_target_properties (gvm_util_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_util_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (gvm_util_shared SHARED ${FILES})
  set_target_properties (gvm_util_shared PROPERTIES OUTPUT_NAME "gvm_util")
  set_target_properties (gvm_util_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_util_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_util_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_util_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_util_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)


## Install

if (BUILD_STATIC)
  install (TARGETS gvm_util_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/util")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  install (TARGETS gvm_util_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/util")
endif (BUILD_SHARED)

## End
