# SPDX-FileCopyrightText: 2017-2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

# test-hosts executable

include_directories(${GLIB_INCLUDE_DIRS})

if(BUILD_SHARED)
  add_executable(test-hosts test-hosts.c)
  set_target_properties(test-hosts PROPERTIES LINKER_LANGUAGE C)
  target_link_libraries(test-hosts ${LIBGVM_BASE_NAME} -lm ${GLIB_LDFLAGS})
endif(BUILD_SHARED)

## End
