# SPDX-FileCopyrightText: 2009-2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)


## Dependency checks

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

if ($ENV{BUILD_SENTRY})
  find_package (SENTRY REQUIRED)
  if (${SENTRY_FOUND})
    message ("Building with Sentry integration")
    set (SENTRY_LDFLAGS "-lsentry")
    set (SENTRY_INCLUDE_DIR "${CMAKE_INSTALL_PREFIX}/include")
    set (SENTRY_CFLAGS "-I${SENTRY_INCLUDE_DIR}")
    add_definitions (-DHAVE_SENTRY=1)
  endif (${SENTRY_FOUND})
endif ($ENV{BUILD_SENTRY})

include_directories (${GLIB_INCLUDE_DIRS} ${SENTRY_INCLUDE_DIR})

set (FILES array.c credentials.c cvss.c drop_privileges.c hosts.c logging.c
           networking.c nvti.c pidfile.c prefs.c proctitle.c pwpolicy.c
           gvm_sentry.c settings.c strings.c version.c)

set (HEADERS array.h credentials.h cvss.h drop_privileges.h hosts.h logging.h
             networking.h nvti.h pidfile.h prefs.h proctitle.h pwpolicy.h
             gvm_sentry.h settings.h strings.h version.h)

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

  target_link_libraries (gvm_base_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS} ${SENTRY_LDFLAGS})
endif (BUILD_SHARED)

set (LIBGVM_BASE_NAME
     ${LIBGVM_BASE_NAME}
     PARENT_SCOPE)

if (GVM_SYSCONF_DIR)
  add_definitions (-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif (GVM_SYSCONF_DIR)

## Tests

if (BUILD_TESTS)
  add_executable (array-test
                  EXCLUDE_FROM_ALL
                  array_tests.c)

  add_test (array-test array-test)

  target_include_directories (array-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (array-test ${CGREEN_LIBRARIES} ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

  add_executable (cvss-test
                  EXCLUDE_FROM_ALL
                  cvss_tests.c)

  add_test (cvss-test cvss-test)

  target_include_directories (cvss-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (cvss-test ${CGREEN_LIBRARIES} -lm ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

  add_executable (networking-test
                  EXCLUDE_FROM_ALL
                  networking_tests.c)
  add_test (networking-test networking-test)
  set (NETWORKING_TEST_LINKER_WRAP_OPTIONS
      "-Wl,-wrap,g_io_channel_new_file,-wrap,g_io_channel_shutdown")
  target_include_directories (networking-test PRIVATE ${CGREEN_INCLUDE_DIRS} )
  target_link_libraries (networking-test gvm_base_shared ${CGREEN_LIBRARIES} ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS}
                       ${NETWORKING_TEST_LINKER_WRAP_OPTIONS})

  add_executable (version-test
                  EXCLUDE_FROM_ALL
                  version_tests.c)

  add_test (version-test version-test)

  target_include_directories (version-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (version-test ${CGREEN_LIBRARIES}
    ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

  add_executable (nvti-test
                  EXCLUDE_FROM_ALL
                  nvti_tests.c)

  add_test (nvti-test nvti-test)

  target_include_directories (nvti-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (nvti-test ${CGREEN_LIBRARIES}
    ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

  add_executable (hosts-test
                  EXCLUDE_FROM_ALL
                  hosts_tests.c)

  add_test (hosts-test hosts-test)

  target_include_directories (hosts-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (hosts-test  gvm_base_shared gvm_util_shared
    ${CGREEN_LIBRARIES} ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

endif (BUILD_TESTS)


## Install

configure_file (libgvm_base.pc.in ${CMAKE_BINARY_DIR}/libgvm_base.pc @ONLY)

install (DIRECTORY DESTINATION ${GVM_RUN_DIR})

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
