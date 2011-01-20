# OpenVAS
# $Id$
# Description: Common CMake Macros from OpenVAS.
#
# Authors:
# Felix Wolfsteller <felix.wolfsteller@intevation.de>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Add experimental indentation targets, improveable (currently it cleans
## up with anasty trick, output is messy). Target should be conditioned on 
## existence of indent tool.

macro (add_custom_indent_targets FILES)
  foreach (FILE ${ARGV})
    # Create a target that checks whether indent is unhappy, print diff.
    add_custom_command (OUTPUT .indent.${FILE}
                        COMMAND indent --no-tabs --ignore-newlines
                                -l 80 ${FILE} -o .indent.${FILE}
                                && \( diff ${FILE} .indent.${FILE} && rm .indent.${FILE} \)
                                || \( echo "STYLE-WARNING: ${FILE} does not conform to GNU coding style as interpreted by indent"
                                && rm .indent.${FILE} \)
                        DEPENDS ${FILE})
    list (APPEND INDENT_DIFF_FILES .indent.${FILE})
  endforeach (FILE ${ARGV})

  add_custom_target (print-indent-diff
                    DEPENDS ${INDENT_DIFF_FILES})

  add_custom_target (indent indent --no-tabs --ignore-newlines -l 80 ${ARGV})
endmacro (add_custom_indent_targets)
