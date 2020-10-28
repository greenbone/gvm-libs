/* Copyright (C) 2009-2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "cvss.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <math.h>

Describe (cvss);
BeforeEach (cvss)
{
}
AfterEach (cvss)
{
}


/**
 * @brief CVSS base.
 */
struct cvss_base
{
  gchar *vector;  ///< Vector.
  double score;   ///< Score.
};

/**
 * @brief CVSS base type.
 */
typedef struct cvss_base cvss_base_t;


/**
 * @brief Every distinct CVSS vector and score shipped in the feed nvdcve files.
 */
static cvss_base_t
cvss_bases[]
 = {{"AV:A/AC:H/Au:M/C:N/I:P/A:P", 2.7},
    {"AV:A/AC:H/Au:N/C:C/I:C/A:C", 6.8},
    {"AV:A/AC:H/Au:N/C:C/I:N/A:C", 6.2},
    {"AV:A/AC:H/Au:N/C:C/I:P/A:N", 5.3},
    {"AV:A/AC:H/Au:N/C:N/I:N/A:C", 4.6},
    {"AV:A/AC:H/Au:N/C:N/I:N/A:P", 1.8},
    {"AV:A/AC:H/Au:N/C:N/I:P/A:N", 1.8},
    {"AV:A/AC:H/Au:N/C:P/I:N/A:N", 1.8},
    {"AV:A/AC:H/Au:N/C:P/I:N/A:P", 3.2},
    {"AV:A/AC:H/Au:N/C:P/I:P/A:C", 5.8},
    {"AV:A/AC:H/Au:N/C:P/I:P/A:N", 3.2},
    {"AV:A/AC:H/Au:N/C:P/I:P/A:P", 4.3},
    {"AV:A/AC:H/Au:S/C:C/I:C/A:C", 6.5},
    {"AV:A/AC:H/Au:S/C:C/I:N/A:N", 4.3},
    {"AV:A/AC:H/Au:S/C:N/I:N/A:C", 4.3},
    {"AV:A/AC:H/Au:S/C:N/I:N/A:P", 1.4},
    {"AV:A/AC:H/Au:S/C:P/I:N/A:P", 2.9},
    {"AV:A/AC:H/Au:S/C:P/I:P/A:C", 5.5},
    {"AV:A/AC:H/Au:S/C:P/I:P/A:P", 4.0},
    {"AV:A/AC:L/Au:M/C:C/I:C/A:C", 7.2},
    {"AV:A/AC:L/Au:M/C:P/I:P/A:P", 4.7},
    {"AV:A/AC:L/Au:N/C:C/I:C/A:C", 8.3},
    {"AV:A/AC:L/Au:N/C:C/I:C/A:N", 7.8},
    {"AV:A/AC:L/Au:N/C:C/I:N/A:N", 6.1},
    {"AV:A/AC:L/Au:N/C:C/I:P/A:C", 8.0},
    {"AV:A/AC:L/Au:N/C:N/I:C/A:C", 7.8},
    {"AV:A/AC:L/Au:N/C:N/I:C/A:N", 6.1},
    {"AV:A/AC:L/Au:N/C:N/I:N/A:C", 6.1},
    {"AV:A/AC:L/Au:N/C:N/I:N/A:P", 3.3},
    {"AV:A/AC:L/Au:N/C:N/I:P/A:C", 6.8},
    {"AV:A/AC:L/Au:N/C:N/I:P/A:N", 3.3},
    {"AV:A/AC:L/Au:N/C:N/I:P/A:P", 4.8},
    {"AV:A/AC:L/Au:N/C:P/I:C/A:C", 8.0},
    {"AV:A/AC:L/Au:N/C:P/I:N/A:N", 3.3},
    {"AV:A/AC:L/Au:N/C:P/I:N/A:P", 4.8},
    {"AV:A/AC:L/Au:N/C:P/I:P/A:C", 7.3},
    {"AV:A/AC:L/Au:N/C:P/I:P/A:N", 4.8},
    {"AV:A/AC:L/Au:N/C:P/I:P/A:P", 5.8},
    {"AV:A/AC:L/Au:S/C:C/I:C/A:C", 7.7},
    {"AV:A/AC:L/Au:S/C:C/I:C/A:N", 7.1},
    {"AV:A/AC:L/Au:S/C:C/I:C/A:P", 7.4},
    {"AV:A/AC:L/Au:S/C:C/I:N/A:N", 5.5},
    {"AV:A/AC:L/Au:S/C:C/I:P/A:P", 6.7},
    {"AV:A/AC:L/Au:S/C:N/I:N/A:C", 5.5},
    {"AV:A/AC:L/Au:S/C:N/I:N/A:P", 2.7},
    {"AV:A/AC:L/Au:S/C:N/I:P/A:C", 6.2},
    {"AV:A/AC:L/Au:S/C:N/I:P/A:N", 2.7},
    {"AV:A/AC:L/Au:S/C:N/I:P/A:P", 4.1},
    {"AV:A/AC:L/Au:S/C:P/I:N/A:N", 2.7},
    {"AV:A/AC:L/Au:S/C:P/I:N/A:P", 4.1},
    {"AV:A/AC:L/Au:S/C:P/I:P/A:C", 6.7},
    {"AV:A/AC:L/Au:S/C:P/I:P/A:N", 4.1},
    {"AV:A/AC:L/Au:S/C:P/I:P/A:P", 5.2},
    {"AV:A/AC:M/Au:N/C:C/I:C/A:C", 7.9},
    {"AV:A/AC:M/Au:N/C:C/I:C/A:N", 7.3},
    {"AV:A/AC:M/Au:N/C:C/I:C/A:P", 7.6},
    {"AV:A/AC:M/Au:N/C:C/I:N/A:C", 7.3},
    {"AV:A/AC:M/Au:N/C:C/I:N/A:N", 5.7},
    {"AV:A/AC:M/Au:N/C:C/I:P/A:C", 7.6},
    {"AV:A/AC:M/Au:N/C:C/I:P/A:P", 6.9},
    {"AV:A/AC:M/Au:N/C:N/I:C/A:C", 7.3},
    {"AV:A/AC:M/Au:N/C:N/I:C/A:N", 5.7},
    {"AV:A/AC:M/Au:N/C:N/I:N/A:C", 5.7},
    {"AV:A/AC:M/Au:N/C:N/I:N/A:P", 2.9},
    {"AV:A/AC:M/Au:N/C:N/I:P/A:C", 6.4},
    {"AV:A/AC:M/Au:N/C:N/I:P/A:N", 2.9},
    {"AV:A/AC:M/Au:N/C:N/I:P/A:P", 4.3},
    {"AV:A/AC:M/Au:N/C:P/I:C/A:C", 7.6},
    {"AV:A/AC:M/Au:N/C:P/I:N/A:N", 2.9},
    {"AV:A/AC:M/Au:N/C:P/I:N/A:P", 4.3},
    {"AV:A/AC:M/Au:N/C:P/I:P/A:N", 4.3},
    {"AV:A/AC:M/Au:N/C:P/I:P/A:P", 5.4},
    {"AV:A/AC:M/Au:S/C:C/I:C/A:C", 7.4},
    {"AV:A/AC:M/Au:S/C:C/I:N/A:N", 5.2},
    {"AV:A/AC:M/Au:S/C:N/I:N/A:C", 5.2},
    {"AV:A/AC:M/Au:S/C:N/I:N/A:P", 2.3},
    {"AV:A/AC:M/Au:S/C:N/I:P/A:C", 5.8},
    {"AV:A/AC:M/Au:S/C:N/I:P/A:N", 2.3},
    {"AV:A/AC:M/Au:S/C:N/I:P/A:P", 3.8},
    {"AV:A/AC:M/Au:S/C:P/I:N/A:C", 5.8},
    {"AV:A/AC:M/Au:S/C:P/I:N/A:N", 2.3},
    {"AV:A/AC:M/Au:S/C:P/I:N/A:P", 3.8},
    {"AV:A/AC:M/Au:S/C:P/I:P/A:C", 6.3},
    {"AV:A/AC:M/Au:S/C:P/I:P/A:N", 3.8},
    {"AV:A/AC:M/Au:S/C:P/I:P/A:P", 4.9},
    {"AV:L/AC:H/Au:M/C:C/I:C/A:C", 5.9},
    {"AV:L/AC:H/Au:M/C:N/I:N/A:C", 3.7},
    {"AV:L/AC:H/Au:M/C:P/I:P/A:C", 4.9},
    {"AV:L/AC:H/Au:M/C:P/I:P/A:P", 3.4},
    {"AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2},
    {"AV:L/AC:H/Au:N/C:C/I:C/A:N", 5.6},
    {"AV:L/AC:H/Au:N/C:C/I:C/A:P", 5.9},
    {"AV:L/AC:H/Au:N/C:C/I:N/A:C", 5.6},
    {"AV:L/AC:H/Au:N/C:C/I:N/A:N", 4.0},
    {"AV:L/AC:H/Au:N/C:N/I:C/A:C", 5.6},
    {"AV:L/AC:H/Au:N/C:N/I:C/A:N", 4.0},
    {"AV:L/AC:H/Au:N/C:N/I:N/A:C", 4.0},
    {"AV:L/AC:H/Au:N/C:N/I:N/A:P", 1.2},
    {"AV:L/AC:H/Au:N/C:N/I:P/A:N", 1.2},
    {"AV:L/AC:H/Au:N/C:N/I:P/A:P", 2.6},
    {"AV:L/AC:H/Au:N/C:P/I:N/A:C", 4.7},
    {"AV:L/AC:H/Au:N/C:P/I:N/A:N", 1.2},
    {"AV:L/AC:H/Au:N/C:P/I:N/A:P", 2.6},
    {"AV:L/AC:H/Au:N/C:P/I:P/A:C", 5.2},
    {"AV:L/AC:H/Au:N/C:P/I:P/A:N", 2.6},
    {"AV:L/AC:H/Au:N/C:P/I:P/A:P", 3.7},
    {"AV:L/AC:H/Au:S/C:C/I:C/A:C", 6.0},
    {"AV:L/AC:H/Au:S/C:C/I:C/A:N", 5.5},
    {"AV:L/AC:H/Au:S/C:C/I:N/A:N", 3.8},
    {"AV:L/AC:H/Au:S/C:N/I:C/A:C", 5.5},
    {"AV:L/AC:H/Au:S/C:N/I:C/A:N", 3.8},
    {"AV:L/AC:H/Au:S/C:N/I:N/A:C", 3.8},
    {"AV:L/AC:H/Au:S/C:N/I:N/A:P", 1.0},
    {"AV:L/AC:H/Au:S/C:N/I:P/A:N", 1.0},
    {"AV:L/AC:H/Au:S/C:N/I:P/A:P", 2.4},
    {"AV:L/AC:H/Au:S/C:P/I:N/A:N", 1.0},
    {"AV:L/AC:H/Au:S/C:P/I:N/A:P", 2.4},
    {"AV:L/AC:H/Au:S/C:P/I:P/A:N", 2.4},
    {"AV:L/AC:H/Au:S/C:P/I:P/A:P", 3.5},
    {"AV:L/AC:L/Au:M/C:C/I:C/A:C", 6.5},
    {"AV:L/AC:L/Au:M/C:N/I:N/A:C", 4.3},
    {"AV:L/AC:L/Au:M/C:P/I:N/A:N", 1.4},
    {"AV:L/AC:L/Au:N/C:C/I:C/A:C", 7.2},
    {"AV:L/AC:L/Au:N/C:C/I:C/A:N", 6.6},
    {"AV:L/AC:L/Au:N/C:C/I:C/A:P", 6.8},
    {"AV:L/AC:L/Au:N/C:C/I:N/A:C", 6.6},
    {"AV:L/AC:L/Au:N/C:C/I:N/A:N", 4.9},
    {"AV:L/AC:L/Au:N/C:C/I:P/A:P", 6.1},
    {"AV:L/AC:L/Au:N/C:N/I:C/A:C", 6.6},
    {"AV:L/AC:L/Au:N/C:N/I:C/A:N", 4.9},
    {"AV:L/AC:L/Au:N/C:N/I:N/A:C", 4.9},
    {"AV:L/AC:L/Au:N/C:N/I:N/A:N", 0.0},
    {"AV:L/AC:L/Au:N/C:N/I:N/A:P", 2.1},
    {"AV:L/AC:L/Au:N/C:N/I:P/A:C", 5.6},
    {"AV:L/AC:L/Au:N/C:N/I:P/A:N", 2.1},
    {"AV:L/AC:L/Au:N/C:N/I:P/A:P", 3.6},
    {"AV:L/AC:L/Au:N/C:P/I:C/A:C", 6.8},
    {"AV:L/AC:L/Au:N/C:P/I:C/A:N", 5.6},
    {"AV:L/AC:L/Au:N/C:P/I:C/A:P", 6.1},
    {"AV:L/AC:L/Au:N/C:P/I:N/A:C", 5.6},
    {"AV:L/AC:L/Au:N/C:P/I:N/A:N", 2.1},
    {"AV:L/AC:L/Au:N/C:P/I:N/A:P", 3.6},
    {"AV:L/AC:L/Au:N/C:P/I:P/A:C", 6.1},
    {"AV:L/AC:L/Au:N/C:P/I:P/A:N", 3.6},
    {"AV:L/AC:L/Au:N/C:P/I:P/A:P", 4.6},
    {"AV:L/AC:L/Au:S/C:C/I:C/A:C", 6.8},
    {"AV:L/AC:L/Au:S/C:C/I:C/A:N", 6.2},
    {"AV:L/AC:L/Au:S/C:C/I:N/A:N", 4.6},
    {"AV:L/AC:L/Au:S/C:C/I:N/A:P", 5.2},
    {"AV:L/AC:L/Au:S/C:N/I:C/A:C", 6.2},
    {"AV:L/AC:L/Au:S/C:N/I:C/A:N", 4.6},
    {"AV:L/AC:L/Au:S/C:N/I:N/A:C", 4.6},
    {"AV:L/AC:L/Au:S/C:N/I:N/A:P", 1.7},
    {"AV:L/AC:L/Au:S/C:N/I:P/A:C", 5.2},
    {"AV:L/AC:L/Au:S/C:N/I:P/A:N", 1.7},
    {"AV:L/AC:L/Au:S/C:N/I:P/A:P", 3.2},
    {"AV:L/AC:L/Au:S/C:P/I:N/A:N", 1.7},
    {"AV:L/AC:L/Au:S/C:P/I:N/A:P", 3.2},
    {"AV:L/AC:L/Au:S/C:P/I:P/A:C", 5.7},
    {"AV:L/AC:L/Au:S/C:P/I:P/A:N", 3.2},
    {"AV:L/AC:L/Au:S/C:P/I:P/A:P", 4.3},
    {"AV:L/AC:M/Au:M/C:C/I:C/A:C", 6.3},
    {"AV:L/AC:M/Au:M/C:N/I:N/A:C", 4.1},
    {"AV:L/AC:M/Au:M/C:N/I:P/A:P", 2.7},
    {"AV:L/AC:M/Au:M/C:P/I:N/A:N", 1.3},
    {"AV:L/AC:M/Au:N/C:C/I:C/A:C", 6.9},
    {"AV:L/AC:M/Au:N/C:C/I:C/A:N", 6.3},
    {"AV:L/AC:M/Au:N/C:C/I:C/A:P", 6.6},
    {"AV:L/AC:M/Au:N/C:C/I:N/A:C", 6.3},
    {"AV:L/AC:M/Au:N/C:C/I:N/A:N", 4.7},
    {"AV:L/AC:M/Au:N/C:C/I:N/A:P", 5.4},
    {"AV:L/AC:M/Au:N/C:C/I:P/A:C", 6.6},
    {"AV:L/AC:M/Au:N/C:C/I:P/A:N", 5.4},
    {"AV:L/AC:M/Au:N/C:C/I:P/A:P", 5.9},
    {"AV:L/AC:M/Au:N/C:N/I:C/A:C", 6.3},
    {"AV:L/AC:M/Au:N/C:N/I:C/A:N", 4.7},
    {"AV:L/AC:M/Au:N/C:N/I:N/A:C", 4.7},
    {"AV:L/AC:M/Au:N/C:N/I:N/A:P", 1.9},
    {"AV:L/AC:M/Au:N/C:N/I:P/A:C", 5.4},
    {"AV:L/AC:M/Au:N/C:N/I:P/A:N", 1.9},
    {"AV:L/AC:M/Au:N/C:N/I:P/A:P", 3.3},
    {"AV:L/AC:M/Au:N/C:P/I:C/A:C", 6.6},
    {"AV:L/AC:M/Au:N/C:P/I:C/A:N", 5.4},
    {"AV:L/AC:M/Au:N/C:P/I:N/A:C", 5.4},
    {"AV:L/AC:M/Au:N/C:P/I:N/A:N", 1.9},
    {"AV:L/AC:M/Au:N/C:P/I:N/A:P", 3.3},
    {"AV:L/AC:M/Au:N/C:P/I:P/A:C", 5.9},
    {"AV:L/AC:M/Au:N/C:P/I:P/A:N", 3.3},
    {"AV:L/AC:M/Au:N/C:P/I:P/A:P", 4.4},
    {"AV:L/AC:M/Au:S/C:C/I:C/A:C", 6.6},
    {"AV:L/AC:M/Au:S/C:C/I:C/A:N", 6.0},
    {"AV:L/AC:M/Au:S/C:C/I:N/A:N", 4.4},
    {"AV:L/AC:M/Au:S/C:N/I:C/A:C", 6.0},
    {"AV:L/AC:M/Au:S/C:N/I:N/A:C", 4.4},
    {"AV:L/AC:M/Au:S/C:N/I:N/A:P", 1.5},
    {"AV:L/AC:M/Au:S/C:N/I:P/A:N", 1.5},
    {"AV:L/AC:M/Au:S/C:N/I:P/A:P", 3.0},
    {"AV:L/AC:M/Au:S/C:P/I:N/A:N", 1.5},
    {"AV:L/AC:M/Au:S/C:P/I:P/A:C", 5.5},
    {"AV:L/AC:M/Au:S/C:P/I:P/A:N", 3.0},
    {"AV:L/AC:M/Au:S/C:P/I:P/A:P", 4.1},
    {"AV:N/AC:H/Au:M/C:C/I:C/A:C", 6.8},
    {"AV:N/AC:H/Au:M/C:N/I:N/A:P", 1.7},
    {"AV:N/AC:H/Au:M/C:N/I:P/A:N", 1.7},
    {"AV:N/AC:H/Au:M/C:P/I:N/A:N", 1.7},
    {"AV:N/AC:H/Au:M/C:P/I:P/A:N", 3.2},
    {"AV:N/AC:H/Au:M/C:P/I:P/A:P", 4.3},
    {"AV:N/AC:H/Au:N/C:C/I:C/A:C", 7.6},
    {"AV:N/AC:H/Au:N/C:C/I:C/A:N", 7.1},
    {"AV:N/AC:H/Au:N/C:C/I:C/A:P", 7.3},
    {"AV:N/AC:H/Au:N/C:C/I:N/A:C", 7.1},
    {"AV:N/AC:H/Au:N/C:C/I:N/A:N", 5.4},
    {"AV:N/AC:H/Au:N/C:C/I:P/A:C", 7.3},
    {"AV:N/AC:H/Au:N/C:C/I:P/A:N", 6.1},
    {"AV:N/AC:H/Au:N/C:N/I:C/A:C", 7.1},
    {"AV:N/AC:H/Au:N/C:N/I:C/A:N", 5.4},
    {"AV:N/AC:H/Au:N/C:N/I:N/A:C", 5.4},
    {"AV:N/AC:H/Au:N/C:N/I:N/A:P", 2.6},
    {"AV:N/AC:H/Au:N/C:N/I:P/A:C", 6.1},
    {"AV:N/AC:H/Au:N/C:N/I:P/A:N", 2.6},
    {"AV:N/AC:H/Au:N/C:N/I:P/A:P", 4.0},
    {"AV:N/AC:H/Au:N/C:P/I:N/A:N", 2.6},
    {"AV:N/AC:H/Au:N/C:P/I:N/A:P", 4.0},
    {"AV:N/AC:H/Au:N/C:P/I:P/A:C", 6.6},
    {"AV:N/AC:H/Au:N/C:P/I:P/A:N", 4.0},
    {"AV:N/AC:H/Au:N/C:P/I:P/A:P", 5.1},
    {"AV:N/AC:H/Au:S/C:C/I:C/A:C", 7.1},
    {"AV:N/AC:H/Au:S/C:C/I:C/A:N", 6.6},
    {"AV:N/AC:H/Au:S/C:C/I:C/A:P", 6.8},
    {"AV:N/AC:H/Au:S/C:C/I:N/A:C", 6.6},
    {"AV:N/AC:H/Au:S/C:C/I:N/A:N", 4.9},
    {"AV:N/AC:H/Au:S/C:C/I:P/A:P", 6.1},
    {"AV:N/AC:H/Au:S/C:N/I:C/A:C", 6.6},
    {"AV:N/AC:H/Au:S/C:N/I:N/A:C", 4.9},
    {"AV:N/AC:H/Au:S/C:N/I:N/A:P", 2.1},
    {"AV:N/AC:H/Au:S/C:N/I:P/A:C", 5.6},
    {"AV:N/AC:H/Au:S/C:N/I:P/A:N", 2.1},
    {"AV:N/AC:H/Au:S/C:N/I:P/A:P", 3.6},
    {"AV:N/AC:H/Au:S/C:P/I:N/A:N", 2.1},
    {"AV:N/AC:H/Au:S/C:P/I:N/A:P", 3.6},
    {"AV:N/AC:H/Au:S/C:P/I:P/A:C", 6.1},
    {"AV:N/AC:H/Au:S/C:P/I:P/A:N", 3.6},
    {"AV:N/AC:H/Au:S/C:P/I:P/A:P", 4.6},
    {"AV:N/AC:L/Au:M/C:C/I:C/A:C", 8.3},
    {"AV:N/AC:L/Au:M/C:C/I:C/A:N", 7.7},
    {"AV:N/AC:L/Au:M/C:N/I:N/A:C", 6.1},
    {"AV:N/AC:L/Au:M/C:N/I:N/A:P", 3.3},
    {"AV:N/AC:L/Au:M/C:N/I:P/A:N", 3.3},
    {"AV:N/AC:L/Au:M/C:P/I:P/A:N", 4.7},
    {"AV:N/AC:L/Au:M/C:P/I:P/A:P", 5.8},
    {"AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
    {"AV:N/AC:L/Au:N/C:C/I:C/A:N", 9.4},
    {"AV:N/AC:L/Au:N/C:C/I:C/A:P", 9.7},
    {"AV:N/AC:L/Au:N/C:C/I:N/A:C", 9.4},
    {"AV:N/AC:L/Au:N/C:C/I:N/A:N", 7.8},
    {"AV:N/AC:L/Au:N/C:C/I:N/A:P", 8.5},
    {"AV:N/AC:L/Au:N/C:C/I:P/A:N", 8.5},
    {"AV:N/AC:L/Au:N/C:C/I:P/A:P", 9.0},
    {"AV:N/AC:L/Au:N/C:N/I:C/A:C", 9.4},
    {"AV:N/AC:L/Au:N/C:N/I:C/A:N", 7.8},
    {"AV:N/AC:L/Au:N/C:N/I:C/A:P", 8.5},
    {"AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8},
    {"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0.0},
    {"AV:N/AC:L/Au:N/C:N/I:N/A:P", 5.0},
    {"AV:N/AC:L/Au:N/C:N/I:P/A:C", 8.5},
    {"AV:N/AC:L/Au:N/C:N/I:P/A:N", 5.0},
    {"AV:N/AC:L/Au:N/C:N/I:P/A:P", 6.4},
    {"AV:N/AC:L/Au:N/C:P/I:C/A:C", 9.7},
    {"AV:N/AC:L/Au:N/C:P/I:C/A:N", 8.5},
    {"AV:N/AC:L/Au:N/C:P/I:C/A:P", 9.0},
    {"AV:N/AC:L/Au:N/C:P/I:N/A:C", 8.5},
    {"AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0},
    {"AV:N/AC:L/Au:N/C:P/I:N/A:P", 6.4},
    {"AV:N/AC:L/Au:N/C:P/I:P/A:C", 9.0},
    {"AV:N/AC:L/Au:N/C:P/I:P/A:N", 6.4},
    {"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
    {"AV:N/AC:L/Au:S/C:C/I:C/A:C", 9.0},
    {"AV:N/AC:L/Au:S/C:C/I:C/A:N", 8.5},
    {"AV:N/AC:L/Au:S/C:C/I:C/A:P", 8.7},
    {"AV:N/AC:L/Au:S/C:C/I:N/A:C", 8.5},
    {"AV:N/AC:L/Au:S/C:C/I:N/A:N", 6.8},
    {"AV:N/AC:L/Au:S/C:C/I:N/A:P", 7.5},
    {"AV:N/AC:L/Au:S/C:C/I:P/A:C", 8.7},
    {"AV:N/AC:L/Au:S/C:C/I:P/A:N", 7.5},
    {"AV:N/AC:L/Au:S/C:C/I:P/A:P", 8.0},
    {"AV:N/AC:L/Au:S/C:N/I:C/A:C", 8.5},
    {"AV:N/AC:L/Au:S/C:N/I:C/A:N", 6.8},
    {"AV:N/AC:L/Au:S/C:N/I:C/A:P", 7.5},
    {"AV:N/AC:L/Au:S/C:N/I:N/A:C", 6.8},
    {"AV:N/AC:L/Au:S/C:N/I:N/A:P", 4.0},
    {"AV:N/AC:L/Au:S/C:N/I:P/A:C", 7.5},
    {"AV:N/AC:L/Au:S/C:N/I:P/A:N", 4.0},
    {"AV:N/AC:L/Au:S/C:N/I:P/A:P", 5.5},
    {"AV:N/AC:L/Au:S/C:P/I:C/A:C", 8.7},
    {"AV:N/AC:L/Au:S/C:P/I:C/A:N", 7.5},
    {"AV:N/AC:L/Au:S/C:P/I:C/A:P", 8.0},
    {"AV:N/AC:L/Au:S/C:P/I:N/A:C", 7.5},
    {"AV:N/AC:L/Au:S/C:P/I:N/A:N", 4.0},
    {"AV:N/AC:L/Au:S/C:P/I:N/A:P", 5.5},
    {"AV:N/AC:L/Au:S/C:P/I:P/A:C", 8.0},
    {"AV:N/AC:L/Au:S/C:P/I:P/A:N", 5.5},
    {"AV:N/AC:L/Au:S/C:P/I:P/A:P", 6.5},
    {"AV:N/AC:M/Au:M/C:C/I:C/A:C", 7.9},
    {"AV:N/AC:M/Au:M/C:N/I:N/A:C", 5.7},
    {"AV:N/AC:M/Au:M/C:N/I:N/A:P", 2.8},
    {"AV:N/AC:M/Au:M/C:N/I:P/A:N", 2.8},
    {"AV:N/AC:M/Au:M/C:N/I:P/A:P", 4.3},
    {"AV:N/AC:M/Au:M/C:P/I:N/A:N", 2.8},
    {"AV:N/AC:M/Au:M/C:P/I:P/A:N", 4.3},
    {"AV:N/AC:M/Au:M/C:P/I:P/A:P", 5.4},
    {"AV:N/AC:M/Au:N/C:C/I:C/A:C", 9.3},
    {"AV:N/AC:M/Au:N/C:C/I:C/A:N", 8.8},
    {"AV:N/AC:M/Au:N/C:C/I:N/A:N", 7.1},
    {"AV:N/AC:M/Au:N/C:C/I:P/A:C", 9.0},
    {"AV:N/AC:M/Au:N/C:C/I:P/A:N", 7.8},
    {"AV:N/AC:M/Au:N/C:C/I:P/A:P", 8.3},
    {"AV:N/AC:M/Au:N/C:N/I:C/A:C", 8.8},
    {"AV:N/AC:M/Au:N/C:N/I:C/A:N", 7.1},
    {"AV:N/AC:M/Au:N/C:N/I:N/A:C", 7.1},
    {"AV:N/AC:M/Au:N/C:N/I:N/A:P", 4.3},
    {"AV:N/AC:M/Au:N/C:N/I:P/A:C", 7.8},
    {"AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3},
    {"AV:N/AC:M/Au:N/C:N/I:P/A:P", 5.8},
    {"AV:N/AC:M/Au:N/C:P/I:C/A:C", 9.0},
    {"AV:N/AC:M/Au:N/C:P/I:C/A:N", 7.8},
    {"AV:N/AC:M/Au:N/C:P/I:C/A:P", 8.3},
    {"AV:N/AC:M/Au:N/C:P/I:N/A:C", 7.8},
    {"AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3},
    {"AV:N/AC:M/Au:N/C:P/I:N/A:P", 5.8},
    {"AV:N/AC:M/Au:N/C:P/I:P/A:C", 8.3},
    {"AV:N/AC:M/Au:N/C:P/I:P/A:N", 5.8},
    {"AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8},
    {"AV:N/AC:M/Au:S/C:C/I:C/A:C", 8.5},
    {"AV:N/AC:M/Au:S/C:C/I:C/A:N", 7.9},
    {"AV:N/AC:M/Au:S/C:C/I:C/A:P", 8.2},
    {"AV:N/AC:M/Au:S/C:C/I:N/A:C", 7.9},
    {"AV:N/AC:M/Au:S/C:C/I:N/A:N", 6.3},
    {"AV:N/AC:M/Au:S/C:C/I:P/A:N", 7.0},
    {"AV:N/AC:M/Au:S/C:C/I:P/A:P", 7.5},
    {"AV:N/AC:M/Au:S/C:N/I:C/A:C", 7.9},
    {"AV:N/AC:M/Au:S/C:N/I:C/A:N", 6.3},
    {"AV:N/AC:M/Au:S/C:N/I:N/A:C", 6.3},
    {"AV:N/AC:M/Au:S/C:N/I:N/A:N", 0.0},
    {"AV:N/AC:M/Au:S/C:N/I:N/A:P", 3.5},
    {"AV:N/AC:M/Au:S/C:N/I:P/A:C", 7.0},
    {"AV:N/AC:M/Au:S/C:N/I:P/A:N", 3.5},
    {"AV:N/AC:M/Au:S/C:N/I:P/A:P", 4.9},
    {"AV:N/AC:M/Au:S/C:P/I:C/A:C", 8.2},
    {"AV:N/AC:M/Au:S/C:P/I:C/A:N", 7.0},
    {"AV:N/AC:M/Au:S/C:P/I:N/A:C", 7.0},
    {"AV:N/AC:M/Au:S/C:P/I:N/A:N", 3.5},
    {"AV:N/AC:M/Au:S/C:P/I:N/A:P", 4.9},
    {"AV:N/AC:M/Au:S/C:P/I:P/A:C", 7.5},
    {"AV:N/AC:M/Au:S/C:P/I:P/A:N", 4.9},
    {"AV:N/AC:M/Au:S/C:P/I:P/A:P", 6.0},
    {NULL, 0.0}};

/* roundup */

Ensure (cvss, roundup_succeeds)
{
  assert_that_double (roundup (0.0), is_equal_to_double (0.0));
  assert_that_double (roundup (1.0), is_equal_to_double (1.0));

  assert_that_double (roundup (1.01), is_equal_to_double (1.1));
  assert_that_double (roundup (0.99), is_equal_to_double (1.0));

  assert_that_double (roundup (1.000001), is_equal_to_double (1.0));
}

/* get_cvss_score_from_base_metrics */

#define CHECK(vector, score)                                               \
  assert_that_double (nearest (get_cvss_score_from_base_metrics (vector)), \
                      is_equal_to_double (score))

Ensure (cvss, get_cvss_score_from_base_metrics_null)
{
  assert_that (get_cvss_score_from_base_metrics (NULL), is_equal_to (-1.0));
}

double
nearest (double cvss)
{
  return round (cvss * 10) / 10;
}

Ensure (cvss, get_cvss_score_from_base_metrics_succeeds)
{
  CHECK ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8);
  CHECK ("AV:N/AC:L/Au:N/C:N/I:N/A:P", 5.0);
  CHECK ("AV:N/AC:M/Au:N/C:N/I:N/A:P", 4.3);
  CHECK ("AV:N/AC:L/Au:N/C:N/I:N/A:N", 0.0);
}

Ensure (cvss, get_cvss_score_from_base_metrics_succeeds_v3)
{
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N", 2.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0);

  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 2.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0);

  /* Trailing separator. */
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N/", 0.0);

  /* We support any case in metrics. */
  CHECK ("CVSS:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:l/a:n", 8.2);
}

Ensure (cvss, get_cvss_score_from_base_metrics_fails)
{
  CHECK ("", -1.0);
  CHECK ("xxx", -1.0);
  CHECK ("//////", -1.0);

  /* Unsupported version. */
  CHECK ("CVSS:3.2/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", -1.0);

  /* Metric name errors. */
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/X:N", -1.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/X:L/A:N", -1.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/X:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/X:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UX:N/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PX:L/UI:N/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.1/AV:L/XC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.1/AXV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", -1.0);

  /* Leading separator. */
  CHECK ("/CVSS:3.1/AXV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", -1.0);

  /* Garbage at end of metric value. */
  CHECK ("CVSS:3.0/AV:LX/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:HX/PR:L/UI:N/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:LX/UI:N/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:NX/S:U/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:UX/C:N/I:L/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:NX/I:L/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:LX/A:N", -1.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:NX", -1.0);

  /* Version must be uppercase. */
  CHECK ("cvss:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", -1.0);
}

Ensure (cvss, get_cvss_score_from_base_metrics_all_nist_match)
{
  cvss_base_t *base;

  base = cvss_bases;
  while (base->vector)
    {
      CHECK (base->vector, base->score);
      base++;
    }

  /* Every distinct CVSSv3 vector and score shipped in the feed nvdcve files. */
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:N", 2.6);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H", 5.4);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:L", 3.1);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.2);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H", 5.6);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.8);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 8.3);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", 8.0);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L", 6.4);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.1);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 4.8);
  CHECK ("CVSS:3.0/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 3.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", 6.2);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.2);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.0);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 7.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L", 6.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 5.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.8);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", 6.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H", 5.2);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.6);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 9.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 9.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 7.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N", 7.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 7.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 4.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L", 5.4);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 5.2);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.7);
  CHECK ("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L", 6.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:N/A:N", 2.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L", 3.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", 1.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H", 5.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:L", 3.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N", 1.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.2);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:H", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N", 5.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:H", 5.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:H", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:H", 5.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N", 1.8);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H", 4.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.8);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 7.8);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N", 7.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N", 6.4);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N", 5.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:N", 5.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H", 5.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L", 5.8);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", 4.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", 3.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 2.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H", 5.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 2.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", 2.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N", 2.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 6.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N", 6.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:H/A:N", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L", 4.2);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.2);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.4);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H", 6.2);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 4.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 2.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 2.9);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 7.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.0);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L", 6.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H", 5.8);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 4.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 2.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H", 4.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N", 7.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", 6.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L", 5.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H", 7.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H", 6.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:L", 4.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", 6.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H", 6.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:H", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N", 2.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H", 4.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L", 8.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 8.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H", 8.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H", 8.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", 7.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:L", 5.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N", 3.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H", 8.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:L", 5.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 5.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", 3.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", 7.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:H", 6.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:H", 5.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L", 4.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L", 3.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N", 2.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H", 5.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L", 2.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H", 8.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L", 6.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 7.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.9);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.7);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 6.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", 5.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 4.0);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:H", 8.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L", 7.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", 4.4);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.3);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 3.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:L", 7.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N", 5.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H", 5.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:L", 6.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:L", 5.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H", 5.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N", 2.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N", 2.6);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:N", 4.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N", 2.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L", 7.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L", 6.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N", 4.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:L", 4.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:H", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L", 4.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N", 7.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N", 3.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:N", 5.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:L", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H", 8.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H", 8.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L", 4.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L", 7.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", 7.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L", 7.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H", 7.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.6);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L", 4.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 3.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N", 6.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N", 6.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 3.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N", 3.4);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:N/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", 3.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L", 9.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N", 8.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:H", 8.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L", 6.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H", 8.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L", 6.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:H", 6.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N", 5.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H", 5.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L", 3.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N", 2.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L", 2.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", 8.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N", 6.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N", 6.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:N/A:N", 3.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L", 4.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N", 3.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:N", 4.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H", 4.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L", 9.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 9.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L", 9.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H", 9.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:L", 8.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 7.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H", 9.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N", 8.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", 9.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H", 8.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:L", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N", 5.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N", 7.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H", 8.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:L", 6.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N", 5.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 7.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L", 5.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", 8.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:H", 8.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N", 4.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", 7.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:L", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N", 5.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N", 6.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L", 5.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:L", 4.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H", 7.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N", 5.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L", 4.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N", 3.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H", 5.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L", 3.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L", 10.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", 9.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 9.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 10.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H", 10.0);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H", 9.9);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:L", 7.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N", 8.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:H", 9.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L", 7.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 8.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 5.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", 9.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", 9.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 9.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H", 9.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L", 8.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H", 8.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 9.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H", 8.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:H", 8.2);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 4.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H", 7.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:L", 4.7);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L", 8.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", 5.4);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 6.9);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:L", 6.7);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.0);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L", 7.0);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N", 6.7);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N", 5.6);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:L", 4.6);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.0);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N", 4.5);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N", 5.7);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 4.9);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H", 6.0);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 3.1);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L", 4.8);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.2);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 4.2);
  CHECK ("CVSS:3.0/AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.2);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 3.9);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 3.7);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", 3.9);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 3.9);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 7.4);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L", 7.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 5.9);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L", 5.4);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 2.1);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", 2.1);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 4.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L", 3.9);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.6);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 7.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 6.1);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.6);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 4.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 3.5);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 2.4);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 6.1);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.6);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 2.4);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 4.6);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 2.4);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 4.3);
  CHECK ("CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 2.1);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.8);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L", 4.3);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 8.3);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.1);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 7.9);
  CHECK ("CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 4.8);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.2);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L", 6.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", 6.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L", 2.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.0);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", 7.6);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", 7.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.6);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 9.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 7.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L", 7.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:L", 8.2);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 7.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 4.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", 5.4);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 5.2);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 7.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.7);
  CHECK ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:L", 3.9);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:L", 2.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.1);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L", 4.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:H", 6.9);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.8);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 7.8);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N", 5.6);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:N", 6.4);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H", 5.8);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L", 3.6);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 2.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L", 3.6);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 2.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H", 4.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:L", 7.4);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N", 7.2);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N", 2.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:L", 3.9);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N", 2.5);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 6.7);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L", 4.2);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:H", 6.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.4);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.1);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.0);
  CHECK ("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:L", 7.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N", 6.7);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", 6.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L", 7.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H", 7.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N", 3.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:L", 3.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.7);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", 6.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L", 5.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N", 5.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H", 6.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H", 5.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H", 5.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N", 2.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L", 2.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.7);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:L", 3.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H", 4.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 8.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H", 8.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H", 7.9);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 5.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H", 8.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H", 7.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:L", 5.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L", 3.8);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", 3.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L", 7.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", 7.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:L", 5.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", 3.9);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.8);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H", 6.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L", 3.9);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L", 2.8);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 9.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.7);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 6.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 4.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 5.0);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 3.6);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.3);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 3.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N", 5.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:N", 3.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H", 6.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:L", 3.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:L", 3.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L", 2.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N", 7.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L", 5.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N", 2.6);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N", 2.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L", 6.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 3.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", 3.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N", 3.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L", 6.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N", 4.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:H/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", 3.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H", 4.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", 8.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H", 8.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:L", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L", 4.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L", 7.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H", 7.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", 7.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", 7.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L", 7.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H", 7.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.6);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L", 4.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L", 4.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 3.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N", 8.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:L", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L", 5.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 3.4);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.0);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H", 5.9);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", 3.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:L", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:H", 9.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 5.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L", 6.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:L", 5.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 4.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:H", 6.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H", 6.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", 4.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H", 5.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L", 3.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N", 2.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L", 2.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", 8.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N", 6.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:N", 6.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:H", 6.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N", 6.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:H", 5.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L", 4.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:H/A:N", 4.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N", 2.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L", 9.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 9.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", 8.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H", 9.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", 7.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N", 8.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L", 7.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N", 5.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H", 9.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N", 7.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:L", 6.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 7.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L", 5.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", 8.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H", 8.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L", 8.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", 8.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:L", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N", 4.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", 8.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L", 7.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", 7.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N", 5.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:L", 6.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L", 5.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", 4.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N", 5.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L", 4.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H", 5.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 9.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 10.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L", 9.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H", 9.9);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L", 8.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:L", 7.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H", 10.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N", 8.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", 8.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 5.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", 9.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", 9.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 9.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H", 9.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L", 8.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H", 8.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 9.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L", 8.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", 7.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H", 9.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N", 7.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:H", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 4.7);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L", 8.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", 6.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H", 8.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 6.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:L", 5.6);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", 2.7);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.1);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.4);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.2);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 4.2);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:L", 6.9);
  CHECK ("CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 6.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 7.2);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.2);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", 3.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", 3.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 3.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 7.1);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", 6.2);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 5.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", 4.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H", 5.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L", 4.9);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 4.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", 2.1);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", 5.7);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.6);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N", 5.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", 6.4);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 6.1);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", 6.4);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", 5.2);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.6);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 4.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 3.5);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 2.4);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 6.1);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.6);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 2.4);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 4.6);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 2.4);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 6.6);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 4.3);
  CHECK ("CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 4.3);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, cvss, roundup_succeeds);

  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_null);
  add_test_with_context (suite, cvss,
                         get_cvss_score_from_base_metrics_succeeds);
  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_fails);
  add_test_with_context (suite, cvss,
                         get_cvss_score_from_base_metrics_succeeds_v3);
  add_test_with_context (suite, cvss,
                         get_cvss_score_from_base_metrics_all_nist_match);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
