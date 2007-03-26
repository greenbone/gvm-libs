/*
 *  Copyright (c) Nessus Consulting S.A.R.L., 2000 - 2001
 *  Email: office@nessus.com
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License 
 *  along with this library; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  $Id: harglists.h,v 1.20 2003/12/15 15:54:39 renaud Exp $
 *
 * Author: Jordan Hrycaj <jordan@mjh.teddy-net.com>
 *
 * Jordan re-wrote Renauds idea of an arglists management on top
 * of the hash list manager
 *
 * --------------------------------------------------------------------
 *
 * There is a generic interface to symbolic run time variable managemet.
 * Althoug opaque variable types are supported, the idea is to let the
 * C language use type defs for checking data types as far a possible.
 *
 *
 * 1. Basic data types supported:
 * ==============================
 *
 * ANY:     It means no particular data type at all and is used in special
 *          cases, only. HARG_ANY is frequently used when it is to be
 *          expressed, that the access key for addressing the data is a '\0'
 *          terminated chatacter string.
 *
 * STRING:  Such a data type is stored as a '\0' terminated character string
 *        . It handled similar to a HARG_BLOB data type, but without need to
 *          explicitely state the data length. The storage space for that
 *          kind of data is fully handled by the system but can be mofified,
 *          freely by a user. Once passed anc copied to the data storage of
 *          the system, the '\0' termination character will not be used,
 *          anymore.
 *
 * NSTRING: Not a real data type but rather data of STRING type with
 *          predefined length. Internally, a '\0' terminator will be
 *          appended logically ending up with data of type HARG_STRING.
 *
 * BLOB:    Considered similar as HARG_STRING but without the terminating
 *          '\0', this data type is seen as a Binary Large OBject of bytes
 *          without knowing an internal data structure. The storage space
 *          for that kind of data is fully handled by the system but can be
 *          mofified, freely by a user.
 *
 * PTR      This is a scalar data type and is stored as a (var*)pointer.
 *
 * INT      This is a scalar data type and is stored as a integer.
 *
 * HARG     This type of data is stored similar to a HARG_PTR.  Addressing
 *          such a data record always implies the whole data tree rooted by
 *          this particular data record.
 *
 * These data types above are indexed by a '\0' terminated character string,
 * which pretty much refers to the notion of a variable name. There is
 * another set of data types describing the same contents as stated abuve.
 *
 * The difference is, that these data types are addressed by a reference
 * to a (void*)pointer, rather than a variable name. Formally, you use
 * the same key argument when addressing such a variable. By using other
 * data types the software knows when to process pointer reference rather
 * than a '\0' terminated character string, 
 *
 * PANY     no data type, stands for any data type using a (void*)key type
 *
 * PSTRING  like STRING, but using a (void*)key type
 *
 * PNSTRING like NSTRING, but using a (void*)key type
 *
 * PPTR     like PTR, but using a (void*)key type
 *
 * PINT     like INT, but using a (void*)key type
 *
 * PBLOB    like BLOB, but using a (void*)key type
 *
 * PHARG    like HARG, but using a (void*)key type
 *
 *
 * 1.1 Posix thread support:
 * -------------------------
 *
 * There is no thread support other than running different lists on each
 * thread.  The same harg list descriptor must not e used concurrently.
 * Using the concept remote lists (see chapter 3), there are several
 * models of, how to share and optimize access to a remote list.
 *
 * A remote list can be run locally, so the remoteness is rather virtual
 * than really on another process, but you do not need to know really as
 * the only difference is the response time when accessing data.
 *
 * Running a remote harg list locallly is available without any furher
 * maintenance and actions (see the directive harg_attach() on chapter 14.)
 *
 *
 *
 *
 * 2. Standard error codes
 * =======================
 *
 * When an error is detectes, the global variable errno is set to some
 * error code. While most specific error codes are application dependent,
 * there are some standard codes explained here.
 *
 * 2.1 common error codes:
 * - - - - - - - - - - - -
 *
 *    ENOENT    There was no such record found matching the particular key,
 *              or index..
 * 
 *    EPERM     Although a record matched the particular key, or index it
 *              must not be used due to a failed type check.
 *
 *    EEXISTS   The record could not be created as it was present,
 *              already, eg. when creating exclusively.
 *
 *    EINVAL    Illegal function arguments, as a NULL list descriptor etc.
 *
 *    ELOOP     Recursion to deep when doing some action, eg. on lists
 *              having sublists where a sublist has the root list as a
 *              sublist, see the symbol HLST_MAX_RDEPTH, below.
 *
 *    EAGAIN    Some condition that is considerd impossible, as being unable
 *              to create a new list entry despite the fact, that such an
 *              entry does not exist, yet--try again or abort.
 *
 *    ENOEXEC   Some internal function was called with invalid arguments
 *              (see also ENOEXEC on section 2.2, below)
 *
 * 2.2 error codes with remote lists:
 * - - - - - - - - - - - - - - - - -
 *
 *    EIDRM     The record was marked tainted and is not allowed to be
 *              used in this list.
 *
 *    ENOEXEC   Some call back function on the server was called with
 *              invalid arguments (internal, will be logged on the server)
 *
 *    EBADF     The remote list does not exist (somebody removed it?,
 *              error will be logged on the server)
 *
 *    EBADSLT   The current slot for remote list is currupt and will be
 *              removed (internal error, will be logged on the server)
 *
 *    EFAULT    Bad data record on the remote server (internal error,
 *              should be logged on the server)
 *
 *    EIO       Unspeciefied communication or server error when refering
 *              to the remote archive (will be logged, if detailed
 *              information is available)
 *
 *
 *
 *
 * 3. Remote behavior/cache strategies:
 * ===================================
 *
 * Accessing data on a list declared remote depends on the cache strategy,
 * currently used.
 *
 * 3.4.1 transparent write (H_sWRTHRU):
 * - - - - - - - - -  - - - - - - - - -
 *
 * On adding, deleting, or modifying a single record, the action always
 * takes place remotely and the local list is updated, afrewards. Unless
 * otherwise noted, an action on a single record (not of type HARG, or 
 * PHARG refering to a sublist) on a reomte list is always atomic. 
 *
 * 3.4.2 remote defaults (neither transparent read or write):
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 *
 * The local list is updated from the remote list only if there was
 * no record present, locally. After that, local modification takes
 * place without remote update.
 *
 * Even on deleting when there is no local record, present an update
 * from the remote list might be necessary when type checking is required
 * (which is a weird operation in that context, anyway.)
 *
 *
 *
 *
 * 4. List construction/destruction:
 * =================================
 *
 * harglst*   harg_create              (unsigned estimated_size);
 * harglst*   harg_dup       (harglst*, unsigned estimated_size);
 * void       harg_close     (harglst*);
 * void       harg_close_all (harglst*);
 * void       harg_purge     (harglst*);
 * void       harg_purge_all (harglst*);
 *
 * Both, harg_create() and harg_dup() create new variable lists, the latter
 * function copies the access tree for that list, recursively (see 
 * HARG_HARGLST, above.)
 *
 * The functions harg_close()/harg_close_all() destroy lists locally,
 * the function harg_close_all() destroys all sublists, recursively.
 *
 * The functions harg_purge()/harg_purge_all() act locally the same way as
 * the harg_close()/harg_close_all(), if applied on a remote list, it is
 * destroyed, as well.
 *
 *
 * 4.1 Return value
 * ----------------
 *
 * The return value for harg_create() and harg_dup() are new list pointers,
 * The function harg_create() never returns NULL, but harg_dup() may do
 * when an error occurs while the variable errno is set to some error code.
 *
 * 4.1.1 error codes:
 * - - - - - - - - - 
 *
 *    ELOOP     Recursion to deep when copying the list
 *
 *    see also chapter 2.
 *
 *
 * 4.2 Remote lists
 * ----------------
 *
 * Even if applied on a remote list, the result of harg_dup() is a local
 * list.  And the result of harg_create() is always a local list.
 *
 * 
 *
 *
 * 5. Adding data:
 * ===============
 *
 * hargkey_t *harg_add_string          (harglst*,hargkey_t*,          char*);
 * hargkey_t *harg_add_nstring         (harglst*,hargkey_t*, unsigned,char*);
 * hargkey_t *harg_add_blob            (harglst*,hargkey_t*, unsigned,void*);
 * hargkey_t *harg_add_ptr             (harglst*,hargkey_t*, void*);
 * hargkey_t *harg_add_int             (harglst*,hargkey_t*  int);
 * hargkey_t *harg_add_harg            (harglst*,hargkey_t*  harglst*)
 *
 * hargkey_t *harg_add_pstring         (harglst*,     void*,          char*);
 * hargkey_t *harg_add_pnstring        (harglst*,     void*, unsigned,char*);
 * hargkey_t *harg_add_pblob           (harglst*,     void*, unsigned,void*);
 * hargkey_t *harg_add_pptr            (harglst*,     void*, void*);
 * hargkey_t *harg_add_pint            (harglst*,     void*, int);
 * hargkey_t *harg_add_pharg           (harglst*,     void*, harglst*)
 *
 * hargkey_t *harg_add_default_string  (harglst*,hargkey_t*,          char*);
 * hargkey_t *harg_add_default_nstring (harglst*,hargkey_t*, unsigned,char*);
 * hargkey_t *harg_add_default_blob    (harglst*,hargkey_t*, unsigned,void*);
 * hargkey_t *harg_add_default_ptr     (harglst*,hargkey_t*, void*);
 * hargkey_t *harg_add_default_int     (harglst*,hargkey_t*  int);
 * hargkey_t *harg_add_default_harg    (harglst*,hargkey_t*  harglst*)
 *
 * hargkey_t *harg_add_default_pstring (harglst*,     void*,          char*);
 * hargkey_t *harg_add_default_pnstring(harglst*,     void*, unsigned,char*);
 * hargkey_t *harg_add_default_pblob   (harglst*,     void*, unsigned,void*);
 * hargkey_t *harg_add_default_pptr    (harglst*,     void*, void*);
 * hargkey_t *harg_add_default_pint    (harglst*,     void*  int);
 * hargkey_t *harg_add_default_pharg   (harglst*,     void*  harglst*)
 *
 * Using these functions, some typed data entry is added to the list. The
 * arguments to these fuctions are all similar
 *
 *    <active-list>, <key>, <data ...>
 *
 * where the key type and the data argumments depend on the function name
 * assembled as
 *
 *    "harg_" <action-to-be-performed> "_" <lower-case-data-type>
 *
 * For an explanation of the data types and the particular key format,
 * see chapter 1.
 *
 * As a particular feature, a string with given length (nstring) or a blob
 * might be passed with a NULL pointer.  In this case, a zero data block of
 * the corresponding length is assumed.
 *
 *
 * 4.1 <action-to-be-performed> == "add_default"
 * ---------------------------------------------
 *
 * If an entry with the given key exists, already, the harg_add_default_*()
 * directive will have no effect. Othewise the data specified with the last
 * arguments are stored as defined in chapter 1.
 *
 *
 * 4.2 <action-to-be-performed> == "add"
 * -------------------------------------
 *
 * These functions always overwrite any exixting entry and will store the data
 * specified with the last as defined in chapter 1.
 *
 *
 * 4.3 Return value
 * ----------------
 *
 * The return value is always a pointer to a copy of the second argument,
 * which is the access key which is guaranteed to exists on the same memory
 * location provided:
 * 
 *   + the table entry exists without being overwitten or removed
 *   + the list is not declared remote with cache flushing, enabled.
 *
 * There is no way to check, whether data record has been overwritten other
 * than testing it before it is added.
 *
 * Upon error NULL is returned variable errno is set to some error code.
 *
 *
 *
 *
 * 6. Deleting symbolically accessed data:
 * =======================================
 *
 * int harg_remove         (harglst*,hargkey_t*);
 *
 * int harg_remove_string  (harglst*,hargkey_t*);
 * int harg_remove_blob    (harglst*,hargkey_t*);
 * int harg_remove_ptr     (harglst*,hargkey_t*);
 * int harg_remove_int     (harglst*,hargkey_t*);
 * int harg_remove_harg    (harglst*,hargkey_t*);
 * int harg_remove_any     (harglst*,hargkey_t*);
 *
 * int harg_remove_pstring (harglst*,hargkey_t*);
 * int harg_remove_pblob   (harglst*,hargkey_t*);
 * int harg_remove_pptr    (harglst*,hargkey_t*);
 * int harg_remove_pint    (harglst*,hargkey_t*);
 * int harg_remove_pharg   (harglst*,hargkey_t*);
 * int harg_remove_pany    (harglst*,hargkey_t*);
 *
 * Using these functions, some typed data entry is removed from the list. 
 * The arguments to these fuctions are all similar
 *
 *    <active-list>, <key>
 *
 * where the key type and the data argumments depend on the function name
 * assembled as
 *
 *    "harg_remove_" <lower-case-data-type>
 *
 * For an explanation of the data types and the particular key format,
 * see chapter 1.
 *
 * The particular function harg_remove() is a shortcut for the function
 * harg_remove_any(). If the function matches type and key in the list,
 * the entry is removed.
 *
 *
 * 6.1 Return value
 * ----------------
 *
 * The return value is always a 0, if an entry could be deleted and
 * -1, otherwise while the variable errno is set to some error code.
 *
 *
 * 6.2 Remark
 * ----------
 *
 * Using either function harg_remove_type() or harg_remove_pany() is
 * generally more efficient than the other functions.  This is because
 * no spacufic data type must be compared.
 *
 *
 *
 *
 * 7. Modifying the data contents:
 * ===============================
 *
 * int harg_set_string   (harglst*,hargkey_t*,          char*);
 * int harg_set_nstring  (harglst*,hargkey_t*, unsigned,char*);
 * int harg_set_blob     (harglst*,hargkey_t*, unsigned,void*);
 * int harg_set_ptr      (harglst*,hargkey_t*, void*);
 * int harg_set_int      (harglst*,hargkey_t*, int);
 * int harg_set_harg     (harglst*,hargkey_t*, harglst*);
 *
 * int harg_set_pstring  (harglst*,hargkey_t*,          char*);
 * int harg_set_pnstring (harglst*,hargkey_t*, unsigned,char*);
 * int harg_set_pblob    (harglst*,hargkey_t*, unsigned,void*);
 * int harg_set_pptr     (harglst*,hargkey_t*, void*);
 * int harg_set_pint     (harglst*,hargkey_t*, int);
 * int harg_set_pharg    (harglst*,hargkey_t*, harglst*);
 *
 * An existing table entry is assigned a new value.  The directive
 * will not do some type checking against the internal data type.
 *
 * The arguments to these fuctions are all similar
 *
 *    <active-list>, <key>, <data ...>
 *
 * where the key type and the data argumments depend on the function name
 * assembled as
 *
 *    "harg_set_" <lower-case-data-type>
 *
 * For an explanation of the data types and the particular key format,
 * see chapter 1.
 *
 * As a particular feature, a string with given length (nstring) or a blob
 * might be passed with a NULL pointer.  In this case, a zero data block of
 * the corresponding length is assumed.
 *
 *
 * 7.1 Return value
 * ----------------
 *
 * The return value is always a 0, if an entry could be changed and
 * -1, otherwise while the variable errno is set to some error code.
 *
 *
 *
 *
 * 8. Modifying the data type:
 * ===========================
 *
 * int harg_name_set_string  (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_blob    (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_ptr     (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_int     (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_harg    (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_any     (harglst*,hargkey_t*,hargkey_t*);
 *
 * int harg_name_set_pstring (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_pblob   (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_pptr    (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_pint    (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_pharg   (harglst*,hargkey_t*,hargkey_t*);
 * int harg_name_set_pany    (harglst*,hargkey_t*,hargkey_t*);
 *
 * int harg_type_set_string  (harglst*,hargkey_t*);
 * int harg_type_set_blob    (harglst*,hargkey_t*);
 * int harg_type_set_ptr     (harglst*,hargkey_t*);
 * int harg_type_set_int     (harglst*,hargkey_t*);
 * int harg_type_set_harg    (harglst*,hargkey_t*);
 *
 * int harg_type_set_pstring (harglst*,hargkey_t*);
 * int harg_type_set_pblob   (harglst*,hargkey_t*);
 * int harg_type_set_pptr    (harglst*,hargkey_t*);
 * int harg_type_set_pint    (harglst*,hargkey_t*);
 * int harg_type_set_pharg   (harglst*,hargkey_t*);
 *
 * These functions redefine an existing type of a table entry to a new data
 * type. It only works among the same type groups scalar (ptr, harg, and int)
 * or object (blob and string.)  This means for example, you  can change a
 * blob to a string type and vice versa, but not to a ptr or int type.
 * 
 * The arguments to these fuctions are all similar
 *
 *    <active-list>, <key>
 *
 * where the key type depends on the function name assembled as
 *
 *    "harg_type_set_" <lower-case-data-type>
 *
 * For an explanation of the data types and the particular key format,
 * see chapter 1.
 *
 *
 * 8.1 Return value
 * ----------------
 *
 * The return value is always a 0, if an entry could be changed and
 * -1, otherwise while the variable errno is set to some error code.
 *
 *
 *
 *
 * 9. Increment and decrement operations:
 * ======================================
 *
 * int harg_inc    (harglst*,hargkey_t*);
 * int harg_dec    (harglst*,hargkey_t*);
 * int harg_inc0   (harglst*,hargkey_t*);
 * int harg_dec0   (harglst*,hargkey_t*);
 * int harg_inc1   (harglst*,hargkey_t*);
 * int harg_dec1   (harglst*,hargkey_t*);
 *
 * int harg_pinc   (harglst*,hargkey_t*);
 * int harg_pdec   (harglst*,hargkey_t*);
 * int harg_pinc0  (harglst*,hargkey_t*);
 * int harg_pdec0  (harglst*,hargkey_t*);
 * int harg_pinc1  (harglst*,hargkey_t*);
 * int harg_pdec1  (harglst*,hargkey_t*);
 *
 * int harg_incn   (harglst*,hargkey_t*, int);
 * int harg_decn   (harglst*,hargkey_t*, int);
 * int harg_inc0n  (harglst*,hargkey_t*, int);
 * int harg_dec0n  (harglst*,hargkey_t*, int);
 * int harg_inc1n  (harglst*,hargkey_t*, int);
 * int harg_dec1n  (harglst*,hargkey_t*, int);
 *
 * int harg_pincn  (harglst*,hargkey_t*, int);
 * int harg_pdecn  (harglst*,hargkey_t*, int);
 * int harg_pinc0n (harglst*,hargkey_t*, int);
 * int harg_pdec0n (harglst*,hargkey_t*, int);
 * int harg_pinc1n (harglst*,hargkey_t*, int);
 * int harg_pdec1n (harglst*,hargkey_t*, int);
 *
 * These operationa act upon integer data types, only. The arguments to 
 * these fuctions are all similar
 *
 *    <active-list>, <key>, [ <increment> ]
 *
 * where the key type and the data argumments depend on the function name
 * assembled as
 *
 *    "harg_" <key-type> <modification-type> <special-action> <offset>
 *
 * where
 *
 *    <key-type>           ::=    "" | "p"
 *    <modification-type>  ::= "inc" | "dec"
 *    <special-action>     ::=    "" | "0"   | "1"
 *    <offset>             ::=    "" | "n" 
 *
 * If the <key-type> is "p", a (void*)  pointer argument key type is
 * expected, 
 *
 * On <modification-type> "inc", the data are to be incremented, on
 * "dec" the data are to be decremented.
 *
 * If the <offset> is "n", an extra integer argument with the increment
 * or decrement distance is expected.  Otherwise this value is assumed 1.
 *
 * If the <special-action> is "", nothing particular happens but the
 * value of the data record will be inremented, or decrement.
 *
 * If the <special-action> is "0", a data record will be created
 * automatically upon incementing if it is missing, and deleted 
 * automatically if the result of the decrement would be smaller or
 * equal zero.
 *
 * If the <special-action> is "1", a data record will be created 
 * automatically upon incementing when it is missing, but it is an error
 * if a record it exists and has non-zero value.  Upon decrementing, the
 * data record will be deleted when it becomes zero, but it is an error 
 * if the decrement operation would become smaller zero.
 *
 *
 * 9.1 Return value
 * ----------------
 *
 * The return value is always a integer value of the data record after
 * the increment or decrement operation if no error occurs. If an error
 * occurs, -1 is returned while the global variable errno is set to a
 * non-zero error code.
 *
 *
 *
 *
 *
 * 10. Retrieving data:
 * ====================
 *
 * void      *harg_get         (harglst*, hargkey_t*);
 *
 * char      *harg_get_string  (harglst*, hargkey_t*);
 * void      *harg_get_blob    (harglst*, hargkey_t*);
 * void      *harg_get_ptr     (harglst*, hargkey_t*);
 * int        harg_get_int     (harglst*, hargkey_t*);
 * harglst   *harg_get_harg    (harglst*, hargkey_t*);
 * void      *harg_get_any     (harglst*, hargkey_t*);
 *
 * char      *harg_get_string  (harglst*, hargkey_t*);
 * void      *harg_get_blob    (harglst*, hargkey_t*);
 * void      *harg_get_ptr     (harglst*, hargkey_t*);
 * int        harg_get_int     (harglst*, hargkey_t*);
 * harglst   *harg_get_harg    (harglst*, hargkey_t*);
 * void      *harg_get_pany    (harglst*, hargkey_t*);
 *
 * These functions realize access to the tata contents.  The arguments to
 * these fuctions are all similar
 *
 *    <active-list>, <key>
 *
 * where the key type depends on the function name assembled as
 *
 *    "harg_type_get_" <lower-case-data-type>
 *
 * For an explanation of the data types and the particular key format,
 * see chapter 1.
 *
 * If the function matches type and key in the list, an entry is returned.
 *
 * The particular function harg_get() is a shortcut for the function
 * harg_get_any().
 *
 *
 * 10.1 Return value
 * ----------------
 *
 * The return value is the appropriate data value as indicated by the last
 * part of the function name. With the particular functions  harg_get_any()
 * and  harg_get_pany(), a generic data type is returned to be casted,
 * appropriately.
 *
 * If an error occurs, NULL of 0 is returned while the global variable
 * errno is set to some non-zero error code.
 *
 *
 *
 *
 * 11. Retrieving meta data:
 * ========================
 *
 * unsigned   harg_get_size     (harglst*,hargkey_t*);
 * hargtype_t harg_get_type     (harglst*,hargkey_t*);
 * int        harg_get_origin   (harglst*,hargkey_t*);
 *
 * unsigned   harg_get_psize    (harglst*,hargkey_t*);
 * hargtype_t harg_get_ptype    (harglst*,hargkey_t*);
 * int        harg_get_porigin  (harglst*,hargkey_t*);
 *
 * Internally, these functions work similar to the harg_get_any() and 
 * harg_get_pany() functions described in chapter 8, only that meta 
 * information retrieved rather than the data records themselves.
 *
 * The harg_get_size()/harg_get_psize() functions return the size of the
 * internal data areea, for a scalar type, this is always sizeof (void*).
 *
 *
 * The harg_get_type()/harg_get_ptype() functions return the data type.
 *
 * The harg_get_origin()/harg_get_porigin() functions return some
 * internal flags, for a remoete record an 0 when the data are local,
 * supported flags are
 *
 *    H_sREMOTE  -- record is from a remote list
 *    H_sTAINTED -- tainted record eg.loaded from a server dump
 *    H_sSTICKY  -- record cannot be flushed with the cache 
 *    H_sWRTHRU  -- write through (and cache locally) 
 *
 *
 *
 *
 * 12. Retrieving sorted records:
 * ==============================
 *
 * hargkey_t *harg_get_nth         (harglst*,unsigned);
 *
 * hargkey_t *harg_get_nth_string  (harglst*,unsigned);
 * hargkey_t *harg_get_nth_blob    (harglst*,unsigned);
 * hargkey_t *harg_get_nth_ptr     (harglst*,unsigned);
 * hargkey_t *harg_get_nth_int     (harglst*,unsigned);
 * hargkey_t *harg_get_nth_harg    (harglst*,unsigned);
 * hargkey_t *harg_get_nth_any     (harglst*,unsigned);
 *
 * hargkey_t *harg_get_nth_pstring (harglst*,unsigned);
 * hargkey_t *harg_get_nth_pblob   (harglst*,unsigned);
 * hargkey_t *harg_get_nth_pptr    (harglst*,unsigned);
 * hargkey_t *harg_get_nth_pint    (harglst*,unsigned);
 * hargkey_t *harg_get_nth_pharg   (harglst*,unsigned);
 * hargkey_t *harg_get_nth_pany    (harglst*,unsigned);
 *
 * int harg_csort (harglst*, 
 *                 int (*cmp_cb) (void *desc, harglst*
 *                                hargkey_t *lKey, hargtype_t lType,
 *                                hargkey_t *rKey, hargtype_t rType),
 *                 void *desc);
 *                              
 * The harg_get_nth-functions treat the argument list (first argument)
 * as an ordered one and retrieve the item with the order index given
 * as second argument. The first index is 0.
 *
 * The returned key type depends on the function name assembled as
 *
 *    "harg_get_nth_" <lower-case-data-type>
 *
 * For an explanation of the data types and the particular key format,
 * see chapter 1.
 *
 * If the function matches type and key in the list, an entry is returned.
 *
 * The particular function harg_get_nth() is a shortcut for the function
 * harg_get_nth_any().
 *
 * Key sorting is usually done lexically upon the ASCII strings of a key.
 * For a (void*)key type this is not unique as it depends on the big/little
 * endian way of storing a pointer in memory.
 *
 * For custom sorting, a call back function might be installed using the
 * harg_csort() request. This function only applies to the current list
 * and will not be inherited to sublists.  The default behavior of the
 + sorting will be equibalent to the following call back function:
 *
 * int cmp_cb (void *unused, harglst *not_used,
 *             hargkey_t *lKey, hargtype_t lType,
 *             hargkey_t *rKey, hargtype_t rType) {
 *
 *   // is ptr type key? see hargtype_t definition
 *   int lLen = (lType & 0x1000) ? 4 : strlen (lKey) ;
 *   int rLen = (rType & 0x1000) ? 4 : strlen (rKey) ;
 *
 *   // get the minimum length
 *   int min  = (lLen > rLen) ? lLen : rLen ;
 *
 *   // compare leftmost characters
 *   int test = memcmp (lKey, rKey, min);
 *
 *   // evaluate
 *   return test ? test : (lLen - rLen) ;
 * }
 *
 * Use a NULL entry for the second argument cmp_cb in harg_csort () in
 * order to reinstall the default value.
 *
 *
 * 12.1 Return value
 * --_--------------
 *
 * The return value is always a key pointer, either to a '\0' terminated
 * character string or to a (void*) pointer depending on the argument
 * type.  Upn error, NULL is returned while the variable errno is set to
 * some error code.
 *
 *
 * 12.2 Remark:
 * ------------
 *
 * This function sort the list when it is necessary. So using these
 * functions while adding and deleting records should be handled carefully
 * as either action will cause the list to be resorted befor indexing with
 * the functions above.
 *
 *
 *
 * 
 * 13. Acting on all records of a list
 * ===================================
 *
 * int        harg_do         (harglst*, int(*call_back)(), void*state);
 * where:     int (*call_back) 
 *              (void*state,void*,hargtype_t,unsigned,hargkey_t*);
 *
 * hargwalk  *harg_walk_init  (harglst*);
 * hargkey_t *harg_walk_next  (hargwalk*);
 * hargkey_t *harg_walk_nextT (hargwalk*,hargtype_t*);
 * void       harg_walk_stop  (hargwalk*);
 *
 * You can cycle thtough all records of a given list recurseively with
 * cal back function, or iteratively. 
 *
 * Doing it recursively call harg_do() passing the list to be considered
 * as first argument, a call back function as second one and a generic
 * state pointer als last one.  For each record of the list, the call back
 * function will be called passing the parameters
 *
 *   <generic-state-pointer> <data-value> <data-type> <key> <key-length>
 *
 * so this function may act upon the data contents.
 *
 * Doing it iteratively, using harg_walk_init() you open a walk upon the
 * list given as argument.  The return value from this routine serves as
 * descriptor argument for subsequent calls.  Getting the next list element
 * can be done either with harg_walk_next() or with harg_walk_nextT(), where
 * the latter function optionally passes bach the type of the next function
 * to the variable pointed, to by the second argument (setting it NULL, this
 * variable is ignored.)
 *
 * The return value from harg_walk_next()/harg_walk_nextT() is a key that
 * may be used for other operations. It returns NULL when all list elements
 * are visited, already.
 *
 * With the directive harg_walk_stop() the list walk is closed and the
 * walk decriptor must not be used, anymore.
 *
 *
 * 13.1 Return value
 * --=--------------
 *
 * Doing it recursively, a 0 value is returned upon successful cycling through
 * all list records, a positve value indicates, that not all records have been
 * visited, and -1 indicates an error while the global error variable errno
 * will be set to some error code.  If the call back function returned a
 * non-zero value (negative upon error, positive upon stop request) cycling
 * through the list is immediately stopped and the value returned as result.
 *
 * Doing it iteratively, walk_init() returns a non-zero descriptor, or
 * NULL upon error (with errno set.)  The functions harg_walk_next() or
 * harg_walk_nextT() return character string or to a (void*) pointer
 * depending on the key type, or NULL when all list elements have been
 * visited, while error ins set to 0. On error, also NULL is returned but
 * the variable errno is set to some error code.
 *
  * 13.1.1 particular error codes:
 * - - - - - - - - - - - - - - -
 *
 *    ENOENT    There list has been flushed so the walk was disabled.
 *
 *
 *
 *
 * 14. Attaching/detaching to/from a remote list:
 * ==============================================
 *
 * int harg_attach (int fd, harglst*,
 *                  harglst* lst, const char* remote_name, 
 *                  int(*drain)(void*), void*, int timeout,
 *                  int);
 * int harg_rstrategy            (harglst*,int);
 * int harg_detach               (harglst*,int);
 *
 * The harg_attach() command is used to run a remote list. As a prerequisite,
 * a remote list server must exist, either uaing a communication socket to
 * another process (see harg_lstserver(), below), or running the remote
 * list server locally. With the directive harg_rstrategy(), the overall
 * cache strategy can be controlled as well as whether to reject tainted
 * data records from the remote list.
 *
 *
 * 14.1 Attaching to a remote archive:
 * -----------------------------------
 *
 * Running the remote list server locally usually applies to posix threads
 * and is available without any furher maintenance and actions, to be taken.
 * Also, using this model is the only way to run a harg list thread save
 * when every thread has its own list descriptor attached to the same remote
 * list. The function arguments to the harg_attach() command are
 *
 *    <fd>, <harg-server>, <harg-to-be-attached>, <list-name>, <flags>
 *
 * where the first two arguments <fd>, <harg-server> describe the connection
 * to the remote harg list server, the argument <harg-to-be-attached> is
 * any local harg (e.g. see harg_create() on chapter 4) to be made or
 * attached remotely, <list-name> is (a '\0' terminated character string and)
 * the logic name of the archibe to connect to, and <flags> is the way how to
 * to open and run that list.
 *
 * A for any remote list server run locally, the argument <fd> must be
 * H_fLOCALQ while <harg-server> is any harg list dedicatged to hold the
 * data of the remote list server.
 *
 * For any other connection, <fd> is the TCP socket, or stream id to be used
 * with read/write (or probably send/recv.) The underlying read/write
 * command are provided as call backs from another software layer (though
 * there is no way to change these call backs, currently.)
 *
 * The argument <harg-to-be-attached> is the harg list descriptor that
 * represents the list to be run, remotely. The name of this list is given
 * as <list-name> and is used to uniquely identify the remote list.
 *
 * With the last argument <flags> the open and cache strategy is determined.
 * The <flags> argument is a bit vector, the following bit options are
 * supported:
 *
 * 14.1.1.open procedure flags
 * - - - - - - - - - - - - - -
 *
 *   H_oCREATE  -- create new data base (must not exist) 
 *   H_oTRUNC   -- create unless existing, empty data base
 *   H_oOPEN    -- list does not need to exist when creating 
 *
 * Only one of there symbols is effective at a time. The flag H_oCREATE
 + has precedence over both H_oOPEN and H_oTRUNC, the flag H_oTRUNC implies
 * the actions of the flag H_oOPEN.
 *
 * 14.1.2.data initialization flags
 * - - - - - - - - - - - - - - - - 
 *
 *   H_oCOPY    -- copy local data to the server 
 *   H_oMOVE    -- move local data to the server (delete the local data)
 *   H_oOWRITE  -- overwrite data on the server 
 *
 * The flag H_oMOVE has precedence ofer the flag H_oCOPY. The flag
 * H_oOWRITE makes sense in combination of any flag H_oCOPY and H_oMOVE
 * but is meaningless when set, alone.
 * 
 * 14.1.3.cache strategy flags
 * - - - - - - - - - - - - - -
 *
 *   H_sSTICKY  -- disable flushing the cache
 *   H_sWRTHRU  -- write through (and cache locally) 
 *
 * These bits affect the behaviour after the open phase.  The flag 
 * H_sSTICKY will prevent flushing any local data from the cache (see also 
 * harg_rsrtategy(), below), tha flag H_sWRTHRU will put the local cache
 * in transparent write through mode which directly reflects the remote
 * harg list, on line.
 *
 * 14.1.4.other flags
 * - - - - - -  - - -
 *
 *   H_sTAINTED -- filter out tainted records 
 *
 * Setting this bit, all remote data that are marked insecure are rejected
 * causing an EIDRM error when accessed. 
 *
 * ===============================
 *
 *
 * Operations on a remote archive
 * ------------------------------
 *
 *
 *
 *
 * int harg_rstrategy  (harglst*, int flags);
 * int harg_get_origin (harglst*,hargkey_t*);
 * const char *harg_datadir (const char *); 
 *
 * harg_ddump  (list, filename)
 * harg_store  (list, filename)
 * harg_undump (list, filename)
 * harg_load   (list, filename)
 * harg_merge  (list, filename)

 *
 * ENOSYS     This package has not been compiled with remote list
 *            suppoer

 */

#ifndef __HARGLIST_H__
#define __HARGLIST_H__

#ifdef _CYGWIN_
#undef _WIN32
#endif

typedef
enum _hargtype_t {

  /* bits: 0..7 (0x00ff) is non-null for specific data types
              8 (0x0100) unused
              9 (0x0200) harg list data type
             10 (0x0400) blob/string data type
             11 (0x0800) scalar data type as int, ptr etc.
             13 (0x1000) data type with (void*) key, otherwise char string
             14 (0x2000) remote data type, usually a remote list
  */

  /* ----------------------------------------------------------------------- *
   *         standard data types addressed by a string type key, a           *
   *                \0-terminated character string                           *
   * ----------------------------------------------------------------------- */

  HARG_ANY       = 0x0000,
  HARG_HARG      = 0x0201,
  HARG_STRING    = 0x0401,
  HARG_BLOB,
  /* blob data types follow ... */

  HARG_PTR       = 0x0801,
  HARG_INT,
  /* scalar data types follow ... */

# ifdef ARG_ARGLIST
  HARG_ARGLIST,
# endif

  /* ----------------------------------------------------------------------- *
   *        data types addressed by a (void*) type key, an array of          *
   *    sizeof(void*) bytes -- all types following have the 8th bit set      *
   * ----------------------------------------------------------------------- */

  HARG_PANY      = 0x1000,
  HARG_PHARG     = 0x1201,
  HARG_PSTRING   = 0x1401,
  HARG_PBLOB,
  /* data types follow (same order as above) ... */

  HARG_PPTR      = 0x1801,
  HARG_PINT,
 /* data types follow (same order as above) ... */

# ifdef ARG_ARGLIST
  HARG_PARGLIST,
# endif

  /* ----------------------------------------------------------------------- *
   *              remote data types -- not directly accessible               *
   * ----------------------------------------------------------------------- */
  
  RHARG_ANY      = 0x2000,
  RHARG_HARG     = 0x2201,
  RHARG_PANY     = 0x3000,
  RHARG_PHARG    = 0x3201
} hargtype_t ;


#ifdef __HARG_INTERNAL__
/* data type qualifiers */
#define is_specific_type(t) ((t) & 0x00ff) /* eg. is not HARG_PANY */
#define is_harglst_type(t)  ((t) & 0x0200)
#define is_blob_type(t)     ((t) & 0x0400)
#define is_scalar_type(t)   ((t) & 0x0800)
#define is_ptrkey_type(t)   ((t) & 0x1000)
#define is_remote_type(t)   ((t) & 0x2000)

#define get_local_type(t)   ((t) & 0xDfff) /* off remote bits */
#define get_yekrtp_type(t)  ((t) & 0xEfff) /* off ptr key bits */ 
#define get_simple_type(t)  ((t) & 0xCfff) /* off remote and ptr key bits */ 

#define make_remote_type(t) ((t) | 0x2000) /* set the remote bit */
#endif /* __HARG_INTERNAL__ */


/* ------------------------------------------------------------------------- *
 *                  mode arguments to harg_inct()                            *
 * ------------------------------------------------------------------------- */

typedef  
enum _incmode_t {

  /* bits: 4 (0x0100) increment, otherwise decrement
	   5 (0x0200) data record will be created
	   6 (0x0400) non-zero data record must not exist
	   7 (0x0800) destroy when zero
	   8 (0x1000) record must not become negative
	   9 (0x2000) record must not remain positive
  */
  HARG_INC_OP  = 0x0101, /* normal increment and decrement */
  HARG_DEC_OP  = 0x0001,
  
  HARG_INC0_OP = 0x0301, /* automatically create if necessary */
  HARG_DEC0_OP = 0x0801, /* automatically destroy when smaller or equal 0 */

  HARG_INC1_OP = 0x0701, /* Automatically create if necessary. In
			    addition to that, it is an error if the
			    entry exists and is non-zero */
  HARG_DEC1_OP = 0x1801, /* Automatically destroy, when 0. In addition
			    to that, it is an error if the entry would
			    become negative.*/
  HARG_DEC2_OP = 0x3801 /* Automatically destroy, when 0. In addition
			    to that, it is an error if the entry would
			    remain non-zero.*/
} incmode_t ;

#ifdef __HARG_INTERNAL__
# define inc_op_increments_record(x) ((x) & 0x0100)
# define inc_op_creates_record(x)    ((x) & 0x0200)
# define inc_op_wants_0_record(x)    ((x) & 0x0400)
# define inc_op_destroy0_record(x)   ((x) & 0x0800)
# define inc_op_notnegtv_record(x)   ((x) & 0x1000)
# define inc_op_notpostv_record(x)   ((x) & 0x2000)
#endif /* __HARG_INTERNAL__ */

/* ------------------------------------------------------------------------- *
 *                 descriptors, contants, typedefs                           *
 * ------------------------------------------------------------------------- */

typedef const char hargkey_t ;

#ifdef __HARG_INTERNAL__
typedef 
struct _harglst {
  hlst           *x ;
  short destroy_mode ;
  short       rflags ;  /* open/mode flags for remote processing */
  void       *sorter ;  /* custom sorting defs */
} harglst;
#else

typedef struct _harglst  {char opaq;} harglst;
#endif /* __HARG_INTERNAL__ */

typedef struct _hargwalk {char opaq;} hargwalk;

/* recusion depth, tree walk */
#ifndef HLST_MAX_RDEPTH
#define HLST_MAX_RDEPTH 20
#endif

/* ------------------------------------------------------------------------- *
 *                stategy flags for remote lists and records                 *
 * ------------------------------------------------------------------------- */

#define H_sTAINTED  0x0100 /* filter out tainted records */
#define H_sSTICKY   0x0200 /* cannot be flushed with the cache */
#define H_sREMOTE   0x0800 /* NOOP, indicates remote processing or origin */
#define H_sWRTHRU   0x1000 /* write through (and cache locally) */
#define H_sRECURSE  0x2000 /* apply to all, eg. harg_close_any() */

/* remote open mode/initialization flags */
#define H_oCREATE   0x0002 /* create new data base (must not exist) */
#define H_oOPEN     0x0004 /* data base need not exist when creating */
#define H_oTRUNC    0x0008 /* empty data base */
#define H_oCOPY     0x0010 /* copy data to/from the server */
#define H_oMOVE     0x0020 /* move data to/from the server */
#define H_oOWRITE   0x0040 /* overwrite data on the server */

/* other flags */
#define H_fLOCALQ   0x8000 /* local queue instead of io stream */

/* ------------------------------------------------------------------------- *
 *                         functional interface                              *
 * ------------------------------------------------------------------------- */

extern harglst*    harg_create               (unsigned estimated_size);
extern harglst*    harg_dup        (harglst*, unsigned estimated_size);
extern void        harg_close_any  (harglst*,int);
extern hargkey_t  *harg_addt       (harglst*,hargkey_t*,hargtype_t,int,unsigned,void*);
extern int         harg_inct       (harglst*,hargkey_t*,hargtype_t,incmode_t,int);
extern int         harg_removet    (harglst*,hargkey_t*,hargtype_t);
extern int         harg_renamet    (harglst*,hargkey_t*,hargtype_t,hargkey_t*,hargtype_t);
extern int         harg_set_valuet (harglst*,hargkey_t*,hargtype_t,unsigned,void*);
extern void       *harg_get_valuet (harglst*,hargkey_t*,hargtype_t);
extern hargkey_t  *harg_get_ntht   (harglst*,unsigned,  hargtype_t);
extern int         harg_csort      (harglst*,int(*)(void*,harglst*,hargkey_t*,hargtype_t,hargkey_t*,hargtype_t),void*);
extern hargtype_t  harg_get_typet  (harglst*,hargkey_t*,hargtype_t);
extern unsigned    harg_get_sizet  (harglst*,hargkey_t*,hargtype_t);
extern hargwalk   *harg_walk_init  (harglst*);
extern hargkey_t  *harg_walk_nextT (hargwalk*,hargtype_t*);
extern void        harg_walk_stop  (hargwalk*);
extern void harg_sort(harglst*);

extern int         harg_do         (harglst*, 
   int(*)(void*state,void*data,hargtype_t,unsigned size,hargkey_t*),
   void *state) ;

extern void        harg_dump       (harglst*);
extern void        harg_tracker_flush (void);
extern void        harg_tracker_dump (void);

extern void (*harg_logger(void(*f)(const char *, ...)))(const char *, ...);
extern int    harg_debuglevel (int level); /* set HARG_DEBUG to enable */

/* ------------------------------------------------------------------------- *
 *           remote extensions for the functional interface                  *
 * ------------------------------------------------------------------------- */

extern int         harg_attach     (int fd, harglst* localserver, harglst* lst, const char *name, int (*drain)(void*),void*,int tmo, int flags);
extern int         harg_detach     (harglst*, int flags);
extern int         harg_rstrategy  (harglst*, int flags);
extern int         harg_get_origint(harglst*,hargkey_t*,hargtype_t);
extern int         harg_runserver  (harglst*,int,int (*cb)(void*),void*);
extern void        harg_addacceptor(harglst*,int,void (*cb)(void*,int,int),void*);

extern const char *harg_datadir    (const char *); /* see hlstio_datadir () */
extern int         harg_rdump      (harglst*, const char *fname, int open_flags,   int open_mode);
extern int         harg_rload      (harglst*, const char *fname, int flush_server, int overwrite);

/* ------------------------------------------------------------------------- *
 *                             convenience macros                            *
 * ------------------------------------------------------------------------- */

#define harg_close(               d)              harg_close_any   ((d),                    0)
#define harg_close_all(           d)              harg_close_any   ((d),           H_sRECURSE)
#define harg_purge(               d)              harg_close_any   ((d), H_sWRTHRU)
#define harg_purge_all(           d)              harg_close_any   ((d), H_sWRTHRU|H_sRECURSE)
#define harg_walk_next(           w)              harg_walk_nextT  ((w),0) 

#define harg_ddump(               d,f)            harg_rdump       ((d),(f),O_TRUNC|O_CREAT,0600) /* overwrite file */
#define harg_store(               d,f)            harg_rdump       ((d),(f),        O_CREAT,0600)
#define harg_undump(              d,f)            harg_rload       ((d),(f),              1,   1) /* flush list */
#define harg_load(                d,f)            harg_rload       ((d),(f),              0,   1) /* overwrite list */
#define harg_merge(               d,f)            harg_rload       ((d),(f),              0,   0)

#define harg_add_string(          d,k,  s)        harg_addt        ((d),             (k),HARG_STRING,  1, 0, (void*)(s))
#define harg_add_nstring(         d,k,n,s)        harg_addt        ((d),             (k),HARG_STRING,  1,(n),(void*)(s))
#define harg_add_ptr(             d,k,  q)        harg_addt        ((d),             (k),HARG_PTR,     1, 0,        (q))
#define harg_add_harg(            d,k,  t)        harg_addt        ((d),             (k),HARG_HARGLST, 1, 0,        (t))
#define harg_add_blob(            d,k,l,q)        harg_addt        ((d),             (k),HARG_BLOB,    1,(l),       (q))
#define harg_add_int(             d,k,  n)        harg_addt        ((d),             (k),HARG_INT,     1, 0, (void*)(n))

#define harg_add_pstring(         d,p,  s)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PSTRING, 1, 0, (void*)(s))
#define harg_add_pnstring(        d,p,n,s)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PSTRING, 1,(n),(void*)(s))
#define harg_add_pptr(            d,p,  q)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PPTR,    1, 0,        (q))
#define harg_add_pharg(           d,p,  t)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PHARGLST,1, 0,        (t))
#define harg_add_pblob(           d,p,l,q)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PBLOB,   1,(l),       (q))
#define harg_add_pint(            d,p,  n)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PINT,    1, 0, (void*)(n))

#define harg_add_default_string(  d,k,  s)        harg_addt        ((d),             (k),HARG_STRING,  0, 0, (void*)(s))
#define harg_add_default_nstring( d,k,n,s)        harg_addt        ((d),             (k),HARG_STRING,  0,(n),(void*)(s))
#define harg_add_default_ptr(     d,k,  q)        harg_addt        ((d),             (k),HARG_PTR,     0, 0,        (q))
#define harg_add_default_harg(    d,k,  t)        harg_addt        ((d),             (k),HARG_HARGLST, 0, 0,        (t))
#define harg_add_default_blob(    d,k,l,q)        harg_addt        ((d),             (k),HARG_BLOB,    0,(l),       (q))
#define harg_add_default_int(     d,k,  n)        harg_addt        ((d),             (k),HARG_INT,     0, 0, (void*)(n))

#define harg_add_default_pstring( d,p,  s)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PSTRING, 0, 0, (void*)(s))
#define harg_add_default_pnstring(d,p,n,s)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PSTRING, 0,(n),(void*)(s))
#define harg_add_default_pptr(    d,p,  q)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PPTR,    0, 0,        (q))
#define harg_add_default_pharg(   d,p,  t)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PHARGLST,0, 0,        (t))
#define harg_add_default_pblob(   d,p,l,q)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PBLOB,   0,(l),       (q))
#define harg_add_default_pint(    d,p,  n)        harg_addt        ((d),(hargkey_t*)&(p),HARG_PINT,    0, 0, (void*)(n))

#define harg_set_string(          d,k,  s)        harg_set_valuet  ((d),             (k),HARG_STRING,     0,        (s))
#define harg_set_nstring(         d,k,n,s)        harg_set_valuet  ((d),             (k),HARG_STRING,    (n),       (s))
#define harg_set_ptr(             d,k,  q)        harg_set_valuet  ((d),             (k),HARG_PTR,        0,        (q))
#define harg_set_harg(            d,k,  t)        harg_set_valuet  ((d),             (k),HARG_HARGLST,    0,        (t))
#define harg_set_blob(            d,k,l,q)        harg_set_valuet  ((d),             (k),HARG_BLOB,      (l),       (q))
#define harg_set_int(             d,k,  n)        harg_set_valuet  ((d),             (k),HARG_INT,        0, (void*)(n))

#define harg_set_pstring(         d,p,  s)        harg_set_valuet  ((d),(hargkey_t*)&(p),HARG_PSTRING,    0,        (s))
#define harg_set_pnstring(        d,p,n,s)        harg_set_valuet  ((d),(hargkey_t*)&(p),HARG_PSTRING,   (n),       (s))
#define harg_set_pptr(            d,p,  q)        harg_set_valuet  ((d),(hargkey_t*)&(p),HARG_PPTR,       0,        (q))
#define harg_set_pharg(           d,p,  t)        harg_set_valuet  ((d),(hargkey_t*)&(p),HARG_PHARGLST,   0,        (t))
#define harg_set_pblob(           d,p,l,q)        harg_set_valuet  ((d),(hargkey_t*)&(p),HARG_PBLOB,     (l),       (q))
#define harg_set_pint(            d,p,  n)        harg_set_valuet  ((d),(hargkey_t*)&(p),HARG_PINT,       0, (void*)(n))

#define harg_inc(                 d,k)            harg_inct        ((d),             (k),HARG_INT,  HARG_INC_OP,     1 )
#define harg_dec(                 d,k)            harg_inct        ((d),             (k),HARG_INT,  HARG_DEC_OP,     1 )
#define harg_inc0(                d,k)            harg_inct        ((d),             (k),HARG_INT,  HARG_INC0_OP,    1 )
#define harg_dec0(                d,k)            harg_inct        ((d),             (k),HARG_INT,  HARG_DEC0_OP     1 )
#define harg_inc1(                d,k)            harg_inct        ((d),             (k),HARG_INT,  HARG_INC1_OP,    1 )
#define harg_dec1(                d,k)            harg_inct        ((d),             (k),HARG_INT,  HARG_DEC1_OP,    1 )

#define harg_pinc(                d,p)            harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_INC_OP,     1 )
#define harg_pdec(                d,p)            harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_DEC_OP,     1 )
#define harg_pinc0(               d,p)            harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_INC0_OP,    1 )
#define harg_pdec0(               d,p)            harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_DEC0_OP     1 )
#define harg_pinc1(               d,p)            harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_INC1_OP,    1 )
#define harg_pdec1(               d,p)            harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_DEC1_OP,    1 )

#define harg_incn(                d,k,n)          harg_inct        ((d),             (k),HARG_INT,  HARG_INC_OP,    (n))
#define harg_decn(                d,k,n)          harg_inct        ((d),             (k),HARG_INT,  HARG_DEC_OP,    (n))
#define harg_inc0n(               d,k,n)          harg_inct        ((d),             (k),HARG_INT,  HARG_INC0_OP,   (n))
#define harg_dec0n(               d,k,n)          harg_inct        ((d),             (k),HARG_INT,  HARG_DEC0_OP    (n))
#define harg_inc1n(               d,k,n)          harg_inct        ((d),             (k),HARG_INT,  HARG_INC1_OP,   (n))
#define harg_dec1n(               d,k,n)          harg_inct        ((d),             (k),HARG_INT,  HARG_DEC1_OP,   (n))

#define harg_pincn(               d,p,n)          harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_INC_OP,    (n))
#define harg_pdecn(               d,p,n)          harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_DEC_OP,    (n))
#define harg_pinc0n(              d,p,n)          harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_INC0_OP,   (n))
#define harg_pdec0n(              d,p,n)          harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_DEC0_OP    (n))
#define harg_pinc1n(              d,p,n)          harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_INC1_OP,   (n))
#define harg_pdec1n(              d,p,n)          harg_inct        ((d),(hargkey_t*)&(p),HARG_PINT, HARG_DEC1_OP,   (n))

#define harg_get_string(          d,k)    ((char*)harg_get_valuet  ((d),             (k),HARG_STRING))
#define harg_get_ptr(             d,k)    ((void*)harg_get_valuet  ((d),             (k),HARG_PTR))
#define harg_get_harg(            d,k) ((harglst*)harg_get_valuet  ((d),             (k),HARG_HARGLST))
#define harg_get_blob(            d,k)    ((void*)harg_get_valuet  ((d),             (k),HARG_BLOB))
#define harg_get_int(             d,k)      ((int)harg_get_valuet  ((d),             (k),HARG_INT))
#define harg_get_any(             d,k)            harg_get_valuet  ((d),             (k),HARG_ANY)
#define harg_get(                 d,k)            harg_get_any (d,k)

#define harg_get_pstring(         d,p)    ((char*)harg_get_valuet  ((d),(hargkey_t*)&(p),HARG_PSTRING))
#define harg_get_pptr(            d,p)    ((void*)harg_get_valuet  ((d),(hargkey_t*)&(p),HARG_PPTR))
#define harg_get_pharg(           d,p) ((harglst*)harg_get_valuet  ((d),(hargkey_t*)&(p),HARG_PHARGLST))
#define harg_get_pblob(           d,p)    ((void*)harg_get_valuet  ((d),(hargkey_t*)&(p),HARG_PBLOB))
#define harg_get_pint(            d,p)      ((int)harg_get_valuet  ((d),(hargkey_t*)&(p),HARG_PINT))
#define harg_get_pany(            d,p)            harg_get_valuet  ((d),(hargkey_t*)&(p),HARG_PANY)

#define harg_get_nth_string(      d,n)            harg_get_ntht    ((d),             (n),HARG_STRING)
#define harg_get_nth_ptr(         d,n)            harg_get_ntht    ((d),             (n),HARG_PTR)
#define harg_get_nth_harg(        d,n)            harg_get_ntht    ((d),             (n),HARG_HARGLST)
#define harg_get_nth_blob(        d,n)            harg_get_ntht    ((d),             (n),HARG_BLOB)
#define harg_get_nth_int(         d,n)            harg_get_ntht    ((d),             (n),HARG_INT)
#define harg_get_nth_any(         d,n)            harg_get_ntht    ((d),             (n),HARG_ANY)
#define harg_get_nth(             d,n)            harg_get_nth_any (d,n)

#define harg_get_nth_pstring(     d,n)            harg_get_ntht    ((d),             (n),HARG_PSTRING)
#define harg_get_nth_pptr(        d,n)            harg_get_ntht    ((d),             (n),HARG_PPTR)
#define harg_get_nth_pharg(       d,n)            harg_get_ntht    ((d),             (n),HARG_PHARGLST)
#define harg_get_nth_pblob(       d,n)            harg_get_ntht    ((d),             (n),HARG_PBLOB)
#define harg_get_nth_pint(        d,n)            harg_get_ntht    ((d),             (n),HARG_PINT)
#define harg_get_nth_pany(        d,n)            harg_get_ntht    ((d),             (n),HARG_PANY)

#define harg_get_origin(          d,k)            harg_get_origint ((d),             (k),HARG_ANY)
#define harg_get_size(            d,k)            harg_get_sizet   ((d),             (k),HARG_ANY)
#define harg_get_type(            d,k)            harg_get_typet   ((d),             (k),HARG_ANY)

#define harg_get_porigin(         d,p)            harg_get_origint ((d),(hargkey_t*)&(p),HARG_PANY)
#define harg_get_psize(           d,p)            harg_get_sizet   ((d),(hargkey_t*)&(p),HARG_PANY)
#define harg_get_ptype(           d,p)            harg_get_typet   ((d),(hargkey_t*)&(p),HARG_PANY)

#define harg_remove_string(       d,k)            harg_removet     ((d),             (k),HARG_STRING)
#define harg_remove_ptr(          d,k)            harg_removet     ((d),             (k),HARG_PTR)
#define harg_remove_harg(         d,k)            harg_removet     ((d),             (k),HARG_HARGLST)
#define harg_remove_blob(         d,k)            harg_removet     ((d),             (k),HARG_BLOB)
#define harg_remove_int(          d,k)            harg_removet     ((d),             (k),HARG_INT)
#define harg_remove_any(          d,k)            harg_removet     ((d),             (k),HARG_ANY)
#define harg_remove(              d,k)            harg_remove_any (d,k)

#define harg_remove_pstring(      d,p)            harg_removet     ((d),(hargkey_t*)&(p),HARG_PSTRING)
#define harg_remove_pptr(         d,p)            harg_removet     ((d),(hargkey_t*)&(p),HARG_PPTR)
#define harg_remove_pharg(        d,p)            harg_removet     ((d),(hargkey_t*)&(p),HARG_PHARGLST)
#define harg_remove_pblob(        d,p)            harg_removet     ((d),(hargkey_t*)&(p),HARG_PBLOB)
#define harg_remove_pint(         d,p)            harg_removet     ((d),(hargkey_t*)&(p),HARG_PINT)
#define harg_remove_pany(         d,p)            harg_removet     ((d),(hargkey_t*)&(p),HARG_PANY)

#define harg_name_set_string(     d,k,l)          harg_renamet     ((d),             (k),HARG_ANY,(l),HARG_STRING)
#define harg_name_set_ptr(        d,k,l)          harg_renamet     ((d),             (k),HARG_ANY,(l),HARG_PTR)
#define harg_name_set_harg(       d,k,l)          harg_renamet     ((d),             (k),HARG_ANY,(l),HARG_HARGLST) 
#define harg_name_set_blob(       d,k,l)          harg_renamet     ((d),             (k),HARG_ANY,(l),HARG_BLOB)
#define harg_name_set_int(        d,k,l)          harg_renamet     ((d),             (k),HARG_ANY,(l),HARG_INT)
#define harg_name_set_any(        d,k,l)          harg_renamet     ((d),             (k),HARG_ANY,(l),HARG_INT)

#define harg_name_set_pstring(    d,p,q)          harg_renamet     ((d),(hargkey_t*)&(p),HARG_PANY,(hargkey_t*)&(q),HARG_PSTRING)
#define harg_name_set_pptr(       d,p,q)          harg_renamet     ((d),(hargkey_t*)&(p),HARG_PANY,(hargkey_t*)&(q),HARG_PPTR)
#define harg_name_set_pharg(      d,p,q)          harg_renamet     ((d),(hargkey_t*)&(p),HARG_PANY,(hargkey_t*)&(q),HARG_PHARGLST) 
#define harg_name_set_pblob(      d,p,q)          harg_renamet     ((d),(hargkey_t*)&(p),HARG_PANY,(hargkey_t*)&(q),HARG_PBLOB)
#define harg_name_set_pint(       d,p,q)          harg_renamet     ((d),(hargkey_t*)&(p),HARG_PANY,(hargkey_t*)&(q),HARG_PINT)
#define harg_name_set_pany(       d,p,q)          harg_renamet     ((d),(hargkey_t*)&(p),HARG_PANY,(hargkey_t*)&(q),HARG_PINT)

#define harg_type_set_string(     d,k)            harg_name_set_string  (d,k,0)
#define harg_type_set_ptr(        d,k)            harg_name_set_ptr     (d,k,0)
#define harg_type_set_harg(       d,k)            harg_name_set_harg    (d,k,0)
#define harg_type_set_blob(       d,k)            harg_name_set_blob    (d,k,0)
#define harg_type_set_int(        d,k)            harg_name_set_int     (d,k,0)

#define harg_type_set_pstring(    d,p)            harg_name_set_pstring (d,p,0)
#define harg_type_set_pptr(       d,p)            harg_name_set_pptr    (d,p,0)
#define harg_type_set_pharg(      d,p)            harg_name_set_pharg   (d,p,0)
#define harg_type_set_pblob(      d,p)            harg_name_set_pblob   (d,p,0)
#define harg_type_set_pint(       d,p)            harg_name_set_pint    (d,p,0)


/* ------------------------------------------------------------------------- *
 *                Renaud special & old name compat                           *
 * ------------------------------------------------------------------------- */

#define harg_ptr_add_ptr(     d,p)   harg_add_pptr     (d,p,p)
#define harg_ptr_get_ptr(     d,p)   harg_get_pptr     (d,p)
#define harg_ptr_remove_ptr(  d,p)   harg_remove_pany  (d,p)
#define harg_get_value(       d,k)   harg_get          (d,k)
#define HARG_HARGLST                 HARG_HARG

#endif /* __HARGLIST_H__ */
