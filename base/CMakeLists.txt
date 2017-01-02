# gvm-libs/base
# $Id$
# Description: cmake control for the base library.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (C) 2009,2010,2013 Greenbone Networks GmbH
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

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

## Dependency checks

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

include_directories (${GLIB_INCLUDE_DIRS})

set (FILES array.c credentials.c cvss.c drop_privileges.c networking.c
           nvti.c pidfile.c pwpolicy.c settings.c strings.c)

set (HEADERS array.h credentials.h cvss.h drop_privileges.h networking.h
             nvti.h pidfile.h pwpolicy.h settings.h strings.h)

if (BUILD_STATIC)
  add_library (gvm_base_static STATIC ${FILES})
  set_target_properties (gvm_base_static PROPERTIES OUTPUT_NAME "gvm_base")
  set_target_properties (gvm_base_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_base_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (gvm_base_shared SHARED ${FILES})
  set_target_properties (gvm_base_shared PROPERTIES OUTPUT_NAME "gvm_base")
  set_target_properties (gvm_base_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_base_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_base_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_base_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_base_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)

if (GVM_PID_DIR)
  add_definitions (-DGVM_PID_DIR=\\\"${GVM_PID_DIR}\\\")
endif (GVM_PID_DIR)

add_definitions (-DGVM_SYSCONF_DIR=\\\"${SYSCONFDIR}\\\")

add_custom_indent_targets (${FILES})

## Install
configure_file (libgvm_base.pc.in ${CMAKE_BINARY_DIR}/libgvm_base.pc @ONLY)

install (DIRECTORY DESTINATION ${GVM_PID_DIR})

install (FILES ${CMAKE_BINARY_DIR}/libgvm_base.pc
         DESTINATION ${LIBDIR}/pkgconfig)

if (BUILD_STATIC)
  install (TARGETS gvm_base_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/base")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS gvm_base_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/base")
endif (BUILD_SHARED)

## End
