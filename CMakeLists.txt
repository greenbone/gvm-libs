# SPDX-FileCopyrightText: 2011-2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.5)

message("-- Configuring the Greenbone Vulnerability Management Libraries...")

# VERSION: Always include major, minor and patch level.
project(gvm-libs VERSION 22.31.1 LANGUAGES C)

if(POLICY CMP0005)
  cmake_policy(SET CMP0005 NEW)
endif(POLICY CMP0005)

set(C_STANDARD, 11)
set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

option(BUILD_STATIC "Build static versions of the libraries" OFF)
option(ENABLE_COVERAGE "Enable support for coverage analysis" OFF)
option(BUILD_TESTS "Build tests for the libraries" OFF)
option(OPENVASD "Build openvasd library" ON)
option(ENABLE_AGENTS "Build agent controller library" ON)
option(ENABLE_CREDENTIAL_STORES "Build credential store library" ON)

if(NOT BUILD_STATIC)
  set(BUILD_SHARED ON)
else(NOT BUILD_STATIC)
  set(BUILD_SHARED OFF)
endif(NOT BUILD_STATIC)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

## Retrieve git revision (at configure time)
find_package(Git)

## make format
message(STATUS "Looking for clang-format...")
find_program(CLANG_FORMAT clang-format)

if(CLANG_FORMAT)
  message(STATUS "Looking for clang-format... ${CLANG_FORMAT}")
  add_custom_target(
    format
    COMMAND
      ${CLANG_FORMAT} "-i" "./agent_controller/*.c" "./base/*.c" "./boreas/*.c"
      "./gmp/*.c" "./http_scanner/*.c" "./openvasd/*.c" "./osp/*.c" "./util/*.c"
      "./agent_controller/*.h" "./base/*.h" "./boreas/*.h" "./gmp/*.h"
      "./http_scanner/*.h" "./openvasd/*.h" "./osp/*.h" "./util/*.h"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )
else(CLANG_FORMAT)
  message(STATUS "clang-format not found...")
endif(CLANG_FORMAT)

include(MacroGitGetRevision)

if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if(EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if(GIT_FOUND)
      git_get_revision(${CMAKE_SOURCE_DIR} ProjectRevision)
      set(GIT_REVISION "~git-${ProjectRevision}")
    else(GIT_FOUND)
      set(GIT_REVISION "~git")
    endif(GIT_FOUND)
  endif(EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif(NOT CMAKE_BUILD_TYPE MATCHES "Release")

# Set dev version if this is a development version and not a full release,
# unset (put value 0 or delete line) before a full release and reset after.
set(PROJECT_DEV_VERSION 0)

# If PROJECT_DEV_VERSION is set, the version string will be set to:
#   "major.minor.patch~dev${PROJECT_DEV_VERSION}${GIT_REVISION}"
# If PROJECT_DEV_VERSION is NOT set, the version string will be set to:
#   "major.minor.patch${GIT_REVISION}"
# For CMAKE_BUILD_TYPE "Release" the git revision will be empty.
if(PROJECT_DEV_VERSION)
  set(PROJECT_VERSION_SUFFIX "~dev${PROJECT_DEV_VERSION}")
endif(PROJECT_DEV_VERSION)

set(
  PROJECT_VERSION_STRING
  "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}${PROJECT_VERSION_SUFFIX}${GIT_REVISION}"
)

## CPack configuration

set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_GENERATOR "TGZ")
set(CPACK_INSTALL_CMAKE_PROJECTS ".;gvm-libs;ALL;/")
set(CPACK_MODULE_PATH "")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_TOPLEVEL_TAG "")
set(CPACK_SYSTEM_NAME "")
set(CPACK_TOPLEVEL_TAG "")

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_GIT}")

set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_VENDOR "Greenbone Networks")
set(CPACK_SOURCE_IGNORE_FILES "${CMAKE_BINARY_DIR}" "/.git/" "swp$")

include(CPack)

## Variables

if(SYSCONF_INSTALL_DIR)
  set(SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif(SYSCONF_INSTALL_DIR)

if(NOT SYSCONFDIR)
  set(SYSCONFDIR "/etc")
endif(NOT SYSCONFDIR)

if(NOT EXEC_PREFIX)
  set(EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif(NOT EXEC_PREFIX)

if(NOT BINDIR)
  set(BINDIR "${EXEC_PREFIX}/bin")
endif(NOT BINDIR)

if(NOT SBINDIR)
  set(SBINDIR "${EXEC_PREFIX}/sbin")
endif(NOT SBINDIR)

if(NOT LIBDIR)
  set(_DEFAULT_LIBRARY_INSTALL_DIR lib)
  if(EXISTS "${EXEC_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(_DEFAULT_LIBRARY_INSTALL_DIR lib32)
  endif(EXISTS "${EXEC_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  if(EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_DEFAULT_LIBRARY_INSTALL_DIR lib64)
  endif(EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(LIBRARY_INSTALL_DIR "${_DEFAULT_LIBRARY_INSTALL_DIR}")
  set(LIBDIR "${EXEC_PREFIX}/${LIBRARY_INSTALL_DIR}")
endif(NOT LIBDIR)

if(NOT LOCALSTATEDIR)
  set(LOCALSTATEDIR "/var")
endif(NOT LOCALSTATEDIR)

if(NOT INCLUDEDIR)
  set(INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif(NOT INCLUDEDIR)

if(NOT DATADIR)
  set(DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif(NOT DATADIR)

if(NOT GVM_RUN_DIR)
  set(GVM_RUN_DIR "/run/gvm")
endif(NOT GVM_RUN_DIR)

if(NOT GVM_SYSCONF_DIR)
  set(GVM_SYSCONF_DIR "${SYSCONFDIR}/gvm")
endif(NOT GVM_SYSCONF_DIR)

if(NOT REDIS_SOCKET_PATH)
  set(REDIS_SOCKET_PATH "/run/redis/redis.sock")
endif()

add_definitions(-DREDIS_SOCKET_PATH="${REDIS_SOCKET_PATH}")
message("-- Using redis socket ${REDIS_SOCKET_PATH}")

message("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

if(ENABLE_COVERAGE)
  set(COVERAGE_FLAGS "--coverage -ftest-coverage -fprofile-arcs")
  set(COVERAGE_DIR "${CMAKE_BINARY_DIR}/coverage")
  file(MAKE_DIRECTORY ${COVERAGE_DIR})
  message("-- Code Coverage enabled")
endif(ENABLE_COVERAGE)

set(
  HARDENING_FLAGS
  "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector"
)
set(LINKER_HARDENING_FLAGS "-Wl,-z,relro -Wl,-z,now")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_FLAGS}")
set(
  CMAKE_C_FLAGS_RELEASE
  "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS} ${COVERAGE_FLAGS}"
)

set(
  CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} ${GPGME_C_FLAGS} \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -Wpedantic \
    -Wmissing-prototypes \
    -Wshadow \
    -Wsequence-point \
    -D_ISOC11_SOURCE \
    -D_DEFAULT_SOURCE"
)

## Version

set(LIBGVMCONFIG_VERSION "${PROJECT_VERSION_STRING}")

add_definitions(-DGVM_LIBS_VERSION="${LIBGVMCONFIG_VERSION}")

# Configure Doxyfile with version number
configure_file(doc/Doxyfile.in ${CMAKE_BINARY_DIR}/doc/Doxyfile @ONLY)
configure_file(doc/Doxyfile_full.in ${CMAKE_BINARY_DIR}/doc/Doxyfile_full @ONLY)
configure_file(doc/Doxyfile_xml.in ${CMAKE_BINARY_DIR}/doc/Doxyfile_xml @ONLY)
configure_file(VERSION.in ${CMAKE_BINARY_DIR}/VERSION @ONLY)

## Testing

if(BUILD_TESTS AND NOT SKIP_SRC)
  message("-- Tests enabled.")
  enable_testing()

  include(MacroAddUnitTest)

  find_package(cgreen REQUIRED)

  set(
    TESTS
    array-test
    boreas-alivedetection-test
    boreas-cli-test
    boreas-error-test
    boreas-io-test
    boreas-ping-test
    boreas-sniffer-test
    compressutils-test
    cpeutils-test
    cvss-test
    hosts-test
    json-test
    jsonpull-test
    logging-test
    logging-domain-test
    networking-test
    nvti-test
    osp-test
    passwordbasedauthentication-test
    streamvalidator-test
    test-hosts
    util-test
    version-test
    versionutils-test
    xmlutils-test
  )

  if(OPENVASD)
    list(
      APPEND
      TESTS
      openvasd-test
      http-scanner-test
      container_image_scanner-test
      httputils-test
      vtparser-test
    )
  endif(OPENVASD)

  if(ENABLE_AGENTS)
    list(APPEND TESTS agent-controller-test)
  endif(ENABLE_AGENTS)

  add_custom_target(tests DEPENDS ${TESTS})

  # Code coverage
  if(ENABLE_COVERAGE)
    find_program(GCOVR gcovr)

    if(NOT GCOVR)
      message(FATAL_ERROR "gcovr coverage reporting tool not found")
    endif()

    message("-- Code Coverage Reporting enabled")

    add_custom_target(
      coverage-html
      COMMAND
        ${GCOVR} --html-details ${COVERAGE_DIR}/coverage.html -r
        ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR}
      DEPENDS tests
    )
    add_custom_target(
      coverage-xml
      COMMAND
        ${GCOVR} --xml ${COVERAGE_DIR}/coverage.xml -r ${CMAKE_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}
      DEPENDS tests
    )
    add_custom_target(coverage DEPENDS coverage-xml coverage-html)
  endif(ENABLE_COVERAGE)
endif(BUILD_TESTS AND NOT SKIP_SRC)

add_custom_target(
  clean-coverage
  COMMAND find . -name *.gcda -delete -or -name *.gcno -delete
  COMMAND rm -f ${COVERAGE_DIR}/*
)

## Program

if(NOT SKIP_SRC)
  add_subdirectory(base)
  add_subdirectory(boreas)
  add_subdirectory(util)
  add_subdirectory(osp)
  add_subdirectory(gmp)

  if(OPENVASD)
    add_subdirectory(http)
    add_subdirectory(http_scanner)
    add_subdirectory(openvasd)
    add_subdirectory(container_image_scanner)
  endif(OPENVASD)

  if(ENABLE_AGENTS)
    if(NOT OPENVASD)
      add_subdirectory(http)
    endif(NOT OPENVASD)
    add_subdirectory(agent_controller)
  endif(ENABLE_AGENTS)

  if(ENABLE_CREDENTIAL_STORES)
    if(NOT OPENVASD)
      add_subdirectory(http)
    endif(NOT OPENVASD)
    add_subdirectory(cyberark)
  endif(ENABLE_CREDENTIAL_STORES)
endif(NOT SKIP_SRC)

## Documentation

add_subdirectory(doc)

if(BUILD_TESTS AND NOT SKIP_SRC)
  add_subdirectory(tests)
  add_test(NAME testhosts COMMAND test-hosts localhost)
endif(BUILD_TESTS AND NOT SKIP_SRC)

## End
