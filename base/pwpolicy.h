/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Protos and data structures for pwpolicy checking.
 *
 * This file contains the protos for \ref pwpolicy.c
 */

#ifndef _GVM_BASE_PWPOLICY_H
#define _GVM_BASE_PWPOLICY_H

char *
gvm_validate_password (const char *, const char *);
void
gvm_disable_password_policy (void);

#endif /* not _GVM_BASE_PWPOLICY_H */
