# SPDX-FileCopyrightText: 2015-2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

## Library

include(FindPkgConfig)

if(NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif()

## Dependency checks

pkg_check_modules(GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules(CURL REQUIRED libcurl>=7.83.0)
pkg_check_modules(CJSON REQUIRED libcjson>=1.7.14)

include_directories(${GLIB_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})

set(FILES agent_controller.c)
set(HEADERS agent_controller.h)

if(BUILD_STATIC)
  add_library(gvm_agent_controller_static STATIC ${FILES})
  set_target_properties(
    gvm_agent_controller_static
    PROPERTIES
      OUTPUT_NAME "gvm_agent_controller"
      CLEAN_DIRECT_OUTPUT 1
      PUBLIC_HEADER "${HEADERS}"
  )
endif()

if(BUILD_SHARED)
  add_library(gvm_agent_controller_shared SHARED ${FILES})
  set_target_properties(
    gvm_agent_controller_shared
    PROPERTIES
      OUTPUT_NAME "gvm_agent_controller"
      CLEAN_DIRECT_OUTPUT 1
      SOVERSION "${PROJECT_VERSION_MAJOR}"
      VERSION "${CPACK_PACKAGE_VERSION}"
      PUBLIC_HEADER "${HEADERS}"
  )

  target_link_libraries(
    gvm_agent_controller_shared
    LINK_PRIVATE
      ${GLIB_LDFLAGS}
      ${CURL_LDFLAGS}
      gvm_http_shared
      gvm_util_shared
      ${LINKER_HARDENING_FLAGS}
  )
endif()

## Tests

if(BUILD_TESTS)
  add_unit_test(
    agent-controller-test
    agent_controller_tests.c
    gvm_base_shared
    gvm_util_shared
    gvm_http_shared
    ${GLIB_LDFLAGS}
    ${CJSON_LDFLAGS}
    ${CURL_LDFLAGS}
    ${LINKER_HARDENING_FLAGS}
  )
endif()

## Install

configure_file(
  libgvm_agent_controller.pc.in
  ${CMAKE_BINARY_DIR}/libgvm_agent_controller.pc
  @ONLY
)

install(
  FILES ${CMAKE_BINARY_DIR}/libgvm_agent_controller.pc
  DESTINATION ${LIBDIR}/pkgconfig
)

if(BUILD_STATIC)
  install(
    TARGETS gvm_agent_controller_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/agent_controller"
  )
endif()

if(BUILD_SHARED)
  install(
    TARGETS gvm_agent_controller_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/agent_controller"
  )
endif()

## End
