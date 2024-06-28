# SPDX-FileCopyrightText: 2015-2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

## Library

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

## Dependency checks

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (GLIB_JSON REQUIRED json-glib-1.0>=1.4.4)
pkg_check_modules (CURL REQUIRED libcurl>=7.74.0)

include_directories (${GLIB_INCLUDE_DIRS} ${GLIB_JSON_INCLUDE_DIRS}
                     ${CURL_INCLUDE_DIRS})

set (FILES openvasd.c)

set (HEADERS openvasd.h)

if (BUILD_STATIC)
  add_library (gvm_openvasd_static STATIC ${FILES})
  set_target_properties (gvm_openvasd_static PROPERTIES OUTPUT_NAME "gvm_openvasd")
  set_target_properties (gvm_openvasd_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_openvasd_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (gvm_openvasd_shared SHARED ${FILES})
  set_target_properties (gvm_openvasd_shared PROPERTIES OUTPUT_NAME "gvm_openvasd")
  set_target_properties (gvm_openvasd_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_openvasd_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_openvasd_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_openvasd_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_openvasd_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${GLIB_JSON_LDFLAGS}
    ${CURL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)


## Tests

if (BUILD_TESTS)
  add_executable (openvasd-test
    EXCLUDE_FROM_ALL
    openvasd_tests.c)

  add_test (openvasd-test openvasd-test)

  target_include_directories (openvasd-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (openvasd-test gvm_base_shared gvm_util_shared
    ${CGREEN_LIBRARIES} ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS}
    )

  add_custom_target (tests-openvasd
    DEPENDS openvasd-test)

endif (BUILD_TESTS)

## Install
configure_file (libgvm_openvasd.pc.in ${CMAKE_BINARY_DIR}/libgvm_openvasd.pc @ONLY)

install (FILES ${CMAKE_BINARY_DIR}/libgvm_openvasd.pc
         DESTINATION ${LIBDIR}/pkgconfig)

if (BUILD_STATIC)
  install (TARGETS gvm_openvasd_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/openvasd")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS gvm_openvasd_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/openvasd")
endif (BUILD_SHARED)

## End
