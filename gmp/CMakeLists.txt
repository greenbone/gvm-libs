# SPDX-FileCopyrightText: 2017-2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

## Library

include(FindPkgConfig)

if(NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif(NOT PKG_CONFIG_FOUND)

## Dependency checks

pkg_check_modules(GLIB REQUIRED glib-2.0>=2.42)

include_directories(${GLIB_INCLUDE_DIRS})

set(FILES gmp.c)

set(HEADERS gmp.h)

if(BUILD_STATIC)
  add_library(gvm_gmp_static STATIC ${FILES})
  set_target_properties(gvm_gmp_static PROPERTIES OUTPUT_NAME "gvm_gmp")
  set_target_properties(gvm_gmp_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties(gvm_gmp_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif(BUILD_STATIC)

if(BUILD_SHARED)
  add_library(gvm_gmp_shared SHARED ${FILES})
  set_target_properties(gvm_gmp_shared PROPERTIES OUTPUT_NAME "gvm_gmp")
  set_target_properties(gvm_gmp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties(
    gvm_gmp_shared
    PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}"
  )
  set_target_properties(
    gvm_gmp_shared
    PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}"
  )
  set_target_properties(gvm_gmp_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries(
    gvm_gmp_shared
    LINK_PRIVATE gvm_util_shared ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS}
  )
endif(BUILD_SHARED)

## Install
configure_file(libgvm_gmp.pc.in ${CMAKE_BINARY_DIR}/libgvm_gmp.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/libgvm_gmp.pc DESTINATION ${LIBDIR}/pkgconfig)

if(BUILD_STATIC)
  install(
    TARGETS gvm_gmp_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/gmp"
  )
endif(BUILD_STATIC)
if(BUILD_SHARED)
  install(
    TARGETS gvm_gmp_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/gmp"
  )
endif(BUILD_SHARED)

## End
