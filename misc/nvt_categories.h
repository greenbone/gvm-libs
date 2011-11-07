/* OpenVAS
 * $Id$
 * Description: Category (ACT_*) definitions.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file
 * This file contains defines for the categories of NVTs.
 * Categories influence the execution order of NVTs (e.g. NVTs with category
 * ACT_SCANNER are in principle executed first).
 */

#ifndef _NVT_CATEGORIES_H
#define _NVT_CATEGORIES_H

/**
 * @brief NVT 'Categories', influence execution order of NVTs.
 *
 * @todo Consider creation of an enumeration.
 */

/** Last plugins actions type. */
#define ACT_LAST                ACT_END
/** First plugins actions type. */
#define ACT_FIRST               ACT_INIT

#define ACT_UNKNOWN             11
#define ACT_END                 10
#define ACT_FLOOD               9
#define ACT_KILL_HOST           8
#define ACT_DENIAL              7
#define ACT_DESTRUCTIVE_ATTACK  6
#define ACT_MIXED_ATTACK        5
#define ACT_ATTACK              4
#define ACT_GATHER_INFO         3
#define ACT_SETTINGS            2
#define ACT_SCANNER             1
#define ACT_INIT                0

#define ACT_STRING_INIT                "init"
#define ACT_STRING_SCANNER             "scanner"
#define ACT_STRING_SETTINGS            "settings"
#define ACT_STRING_GATHER_INFO         "infos"
#define ACT_STRING_ATTACK              "attack"
#define ACT_STRING_MIXED_ATTACK        "mixed"
#define ACT_STRING_DESTRUCTIVE_ATTACK  "destructive_attack"
#define ACT_STRING_DENIAL              "denial"
#define ACT_STRING_KILL_HOST           "kill_host"
#define ACT_STRING_FLOOD               "flood"
#define ACT_STRING_END                 "end"
#define ACT_STRING_UNKNOWN             "unknown"

#define ACT_STRING_LIST_ALL     ACT_STRING_INIT ,               \
                                ACT_STRING_SCANNER ,            \
                                ACT_STRING_SETTINGS ,           \
                                ACT_STRING_GATHER_INFO ,        \
                                ACT_STRING_ATTACK ,             \
                                ACT_STRING_MIXED_ATTACK ,       \
                                ACT_STRING_DESTRUCTIVE_ATTACK , \
                                ACT_STRING_DENIAL ,             \
                                ACT_STRING_KILL_HOST ,          \
                                ACT_STRING_FLOOD ,              \
                                ACT_STRING_END ,                \
                                ACT_STRING_UNKNOWN

#endif /* _NVT_CATEGORIES_H */
