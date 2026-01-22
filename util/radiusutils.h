/* SPDX-FileCopyrightText: 2015-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Headers of an API for Radius authentication.
 */

#ifndef _GVM_UTIL_RADIUSUTILS_H
#define _GVM_UTIL_RADIUSUTILS_H

int
radius_authenticate (const char *, const char *, const char *, const char *);

#endif /* not _GVM_UTIL_RADIUSUTILS_H */
