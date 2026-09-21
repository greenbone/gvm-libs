# SPDX-FileCopyrightText: 2025 Greenbone AG
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

set(FILES ad_connector.c)
set(HEADERS ad_connector.h)

if(BUILD_STATIC)
  add_library(ad_connector_static STATIC ${FILES})
  set_target_properties(
    ad_connector_static
    PROPERTIES OUTPUT_NAME "ad_connector"
  )
  set_target_properties(ad_connector_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties(
    ad_connector_static
    PROPERTIES PUBLIC_HEADER "${HEADERS}"
  )
endif(BUILD_STATIC)

if(BUILD_SHARED)
  add_library(ad_connector_shared SHARED ${FILES})
  set_target_properties(
    ad_connector_shared
    PROPERTIES OUTPUT_NAME "ad_connector"
  )
  set_target_properties(ad_connector_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties(
    ad_connector_shared
    PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}"
  )
  set_target_properties(
    ad_connector_shared
    PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}"
  )
  set_target_properties(
    ad_connector_shared
    PROPERTIES PUBLIC_HEADER "${HEADERS}"
  )

  target_link_libraries(
    ad_connector_shared
    LINK_PRIVATE gvm_ldap_shared ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS}
  )
endif(BUILD_SHARED)

## Tests

if(BUILD_TESTS)
  add_unit_test(
    ad-connector-test
    ad_connector_tests.c
    ad_connector_shared
    gvm_base_shared
    gvm_ldap_shared
    ${GLIB_LDFLAGS}
    ${LINKER_HARDENING_FLAGS}
  )
endif(BUILD_TESTS)

## Install
configure_file(
  libgvm_ad_connector.pc.in
  ${CMAKE_BINARY_DIR}/libgvm_ad_connector.pc
  @ONLY
)

install(
  FILES ${CMAKE_BINARY_DIR}/libgvm_ad_connector.pc
  DESTINATION ${LIBDIR}/pkgconfig
)

if(BUILD_STATIC)
  install(
    TARGETS ad_connector_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/ad_connector"
  )
endif(BUILD_STATIC)
if(BUILD_SHARED)
  install(
    TARGETS ad_connector_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/ad_connector"
  )
endif(BUILD_SHARED)

## End
