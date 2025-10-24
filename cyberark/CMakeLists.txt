# SPDX-FileCopyrightText: 2015-2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

## Library

include(FindPkgConfig)

if(NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif(NOT PKG_CONFIG_FOUND)

## Dependency checks

pkg_check_modules(GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules(CURL REQUIRED libcurl>=7.83.0)
pkg_check_modules(CJSON REQUIRED libcjson>=1.7.14)

include_directories(${GLIB_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})

set(FILES cyberark.c)
set(HEADERS cyberark.h)

if(BUILD_STATIC)
  add_library(gvm_cyberark_static STATIC ${FILES})
  set_target_properties(
    gvm_cyberark_static
    PROPERTIES OUTPUT_NAME "gvm_cyberark"
  )
  set_target_properties(gvm_cyberark_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties(
    gvm_cyberark_static
    PROPERTIES PUBLIC_HEADER "${HEADERS}"
  )
endif(BUILD_STATIC)

if(BUILD_SHARED)
  add_library(gvm_cyberark_shared SHARED ${FILES})
  set_target_properties(
    gvm_cyberark_shared
    PROPERTIES OUTPUT_NAME "gvm_cyberark"
  )
  set_target_properties(gvm_cyberark_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties(
    gvm_cyberark_shared
    PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}"
  )
  set_target_properties(
    gvm_cyberark_shared
    PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}"
  )
  set_target_properties(
    gvm_cyberark_shared
    PROPERTIES PUBLIC_HEADER "${HEADERS}"
  )

  target_link_libraries(
    gvm_cyberark_shared
    LINK_PRIVATE
      gvm_http_shared
      gvm_util_shared
      ${GLIB_LDFLAGS}
      ${CURL_LDFLAGS}
      ${CJSON_LDFLAGS}
      ${LINKER_HARDENING_FLAGS}
  )
endif(BUILD_SHARED)

## Install
configure_file(
  libgvm_cyberark.pc.in
  ${CMAKE_BINARY_DIR}/libgvm_cyberark.pc
  @ONLY
)

install(
  FILES ${CMAKE_BINARY_DIR}/libgvm_cyberark.pc
  DESTINATION ${LIBDIR}/pkgconfig
)

if(BUILD_STATIC)
  install(
    TARGETS gvm_cyberark_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/cyberark"
  )
endif(BUILD_STATIC)
if(BUILD_SHARED)
  install(
    TARGETS gvm_cyberark_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/cyberark"
  )
endif(BUILD_SHARED)

## End
