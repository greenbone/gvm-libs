/* SPDX-FileCopyrightText: 2014-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief API for process title setting.
 */

#ifndef _GVM_PROCTITLE_H
#define _GVM_PROCTITLE_H

void
proctitle_init (int, char **);

void
proctitle_set (const char *, ...);

#endif /* not _GVM_PROCTITLE_H */
