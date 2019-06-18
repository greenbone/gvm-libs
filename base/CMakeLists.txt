# Copyright (C) 2009-2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)


## Dependency checks

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

include_directories (${GLIB_INCLUDE_DIRS})

set (FILES array.c credentials.c cvss.c drop_privileges.c hosts.c logging.c
           networking.c nvti.c pidfile.c prefs.c proctitle.c pwpolicy.c
           settings.c strings.c)

set (HEADERS array.h credentials.h cvss.h drop_privileges.h hosts.h logging.h
             networking.h nvti.h pidfile.h prefs.h proctitle.h pwpolicy.h
             settings.h strings.h)

if (BUILD_STATIC)
  set (LIBGVM_BASE_NAME gvm_base_static)
  add_library (gvm_base_static STATIC ${FILES})
  set_target_properties (gvm_base_static PROPERTIES OUTPUT_NAME "gvm_base")
  set_target_properties (gvm_base_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_base_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  set (LIBGVM_BASE_NAME gvm_base_shared)
  add_library (gvm_base_shared SHARED ${FILES})
  set_target_properties (gvm_base_shared PROPERTIES OUTPUT_NAME "gvm_base")
  set_target_properties (gvm_base_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_base_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_base_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_base_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_base_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)

set (LIBGVM_BASE_NAME
     ${LIBGVM_BASE_NAME}
     PARENT_SCOPE)

if (GVM_PID_DIR)
  add_definitions (-DGVM_PID_DIR="${GVM_PID_DIR}")
endif (GVM_PID_DIR)

if (GVM_SYSCONF_DIR)
  add_definitions (-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif (GVM_SYSCONF_DIR)


## Tests

add_executable (array-test
                EXCLUDE_FROM_ALL
                array_tests.c)

add_test (array-test array-test)

target_link_libraries (array-test cgreen ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

add_custom_target (tests
                   DEPENDS array-test)


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
