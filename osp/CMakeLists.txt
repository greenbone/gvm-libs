# Copyright (C) 2015-2021 Greenbone Networks GmbH
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

## Library

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

## Dependency checks

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

include_directories (${GLIB_INCLUDE_DIRS})

set (FILES osp.c)

set (HEADERS osp.h)

if (BUILD_STATIC)
  add_library (gvm_osp_static STATIC ${FILES})
  set_target_properties (gvm_osp_static PROPERTIES OUTPUT_NAME "gvm_osp")
  set_target_properties (gvm_osp_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_osp_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (gvm_osp_shared SHARED ${FILES})
  set_target_properties (gvm_osp_shared PROPERTIES OUTPUT_NAME "gvm_osp")
  set_target_properties (gvm_osp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_osp_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_osp_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_osp_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_osp_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)


## Tests

if (BUILD_TESTS)
  add_executable (osp-test
    EXCLUDE_FROM_ALL
    osp_tests.c)

  add_test (osp-test osp-test)

  target_include_directories (osp-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (osp-test gvm_base_shared gvm_util_shared
    ${CGREEN_LIBRARIES} ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS}
    )

  add_custom_target (tests-osp
    DEPENDS osp-test)

endif (BUILD_TESTS)

## Install
configure_file (libgvm_osp.pc.in ${CMAKE_BINARY_DIR}/libgvm_osp.pc @ONLY)

install (FILES ${CMAKE_BINARY_DIR}/libgvm_osp.pc
         DESTINATION ${LIBDIR}/pkgconfig)

if (BUILD_STATIC)
  install (TARGETS gvm_osp_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/osp")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS gvm_osp_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/osp")
endif (BUILD_SHARED)

## End
