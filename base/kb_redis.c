/* OpenVAS Libraries
 *
 * Authors:
 * Henri Doreau <henri.doreau@gmail.com>
 *
 * Copyright:
 * Copyright (C) 2014 - Greenbone Networks GmbH.
 *
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
 *
 * Knowledge base management API - Redis backend.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <hiredis/hiredis.h>
#include <glib.h>

#include "kb.h"

#undef  G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  kb_redis"

/**
 * @file kb_redis.c
 *
 * @brief Contains specialized structures and functions to use redis as a KB
 *        server.
 */


/**
 * @brief Name of the namespace usage bitmap in redis.
 */
#define GLOBAL_DBINDEX_NAME "OpenVAS.__GlobalDBIndex"

/**
 * @brief Number of seconds to wait for between two attempts to acquire a KB
 *        namespace.
 */
#define KB_RETRY_DELAY      60


static const struct kb_operations KBRedisOperations;


/**
 * @brief Subclass of struct kb, it contains the redis-specific fields, such as
 *        the redis context, current DB (namespace) id and the server socket
 *        path.
 */
struct kb_redis
{
  struct kb kb;         /**< Parent KB handle. */
  unsigned int max_db;  /**< Max # of databases. */
  unsigned int db;      /**< Namespace ID number, 0 if uninitialized. */
  redisContext *rctx;   /**< Redis client context. */
  char path[0];         /**< Path to the server socket. */
};
#define redis_kb(__kb) ((struct kb_redis *)(__kb))

/**
 * @brief Redis transaction handle.
 */
struct redis_tx
{
  struct kb_redis *kbr; /**< Redis KB handle. */
  bool valid;           /**< Whether the transaction is still valid. */
};


static int redis_delete_all (struct kb_redis *);
static int redis_lnk_reset (kb_t);
static int redis_flush_all (kb_t, const char *);
static redisReply *redis_cmd (struct kb_redis *kbr, const char *fmt, ...)
    __attribute__((__format__(__printf__, 2, 3)));


/**
 * Attempt to atomically acquire ownership of a database.
 */
static int
try_database_index (struct kb_redis *kbr, int index)
{
  redisContext *ctx = kbr->rctx;
  redisReply *rep;
  int rc = 0;

  rep = redisCommand (ctx, "HSETNX %s %d 1", GLOBAL_DBINDEX_NAME, index);
  if (rep == NULL)
    return -ENOMEM;

  if (rep->type != REDIS_REPLY_INTEGER)
    rc = -EPROTO;
  else if (rep->integer == 0)
    rc = -EALREADY;
  else
    kbr->db = index;

  freeReplyObject (rep);

  return rc;
}

/* Redis 2.4.* compatibility mode.
 *
 * Before 2.6.* redis won't tell its clients how many databases have been
 * configured. We can find it empirically by attempting to select a given
 * DB and seeing whether we get an error or not.
 */
#define MAX_DB_INDEX__24    1000

static int
fetch_max_db_index_compat (struct kb_redis *kbr)
{
  redisContext *ctx = kbr->rctx;
  redisReply *rep;
  int min, max;
  int rc = 0;

  min = 1;
  max = MAX_DB_INDEX__24;

  while (min < max)
    {
      int current;

      current = min + ((max - min) / 2);

      rep = redisCommand (ctx, "SELECT %d", current);
      if (rep == NULL)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis command failed with '%s'", __func__, ctx->errstr);
          return -1;
        }

      switch (rep->type)
        {
          case REDIS_REPLY_ERROR:
            max = current;
            break;

          case REDIS_REPLY_STATUS:
            min = current + 1;
            break;

          default:
            g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                   "%s: unexpected reply of type %d", __func__, rep->type);
            freeReplyObject (rep);
            return -1;
        }
      freeReplyObject (rep);
    }

  kbr->max_db = min;

  /* Go back to DB #0 */
  rep = redisCommand (ctx, "SELECT 0");
  if (rep == NULL)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: DB selection failed with '%s'", __func__, ctx->errstr);
      rc = -1;
    }

  if (rep)
    freeReplyObject (rep);

  return rc;
}

static int
fetch_max_db_index (struct kb_redis *kbr)
{
  int rc = 0;
  redisContext *ctx = kbr->rctx;
  redisReply *rep = NULL;

  rep = redisCommand (ctx, "CONFIG GET databases");
  if (rep == NULL)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: redis command failed with '%s'", __func__, ctx->errstr);
      rc = -1;
      goto err_cleanup;
    }

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: cannot retrieve max DB number: %s", __func__, rep->str);
      rc = -1;
      goto err_cleanup;
    }

  if (rep->elements == 0)
    {
      /* Redis 2.4 compatibility mode. Suboptimal... */
      rc = fetch_max_db_index_compat (kbr);
    }
  else if (rep->elements == 2)
    {
      kbr->max_db = (unsigned)atoi(rep->element[1]->str);
    }
  else
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: unexpected reply length (%zd)", __func__, rep->elements);
      rc = -1;
      goto err_cleanup;
    }

  g_debug ("%s: maximum DB number: %u", __func__, kbr->max_db);

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * WARNING: do not call redis_cmd in here, since our context is not fully
 * acquired yet!
 */
static int
select_database (struct kb_redis *kbr)
{
  int rc;
  redisContext *ctx = kbr->rctx;
  redisReply *rep = NULL;

  if (kbr->db == 0)
    {
      unsigned i;

      if (kbr->max_db == 0)
        fetch_max_db_index (kbr);

      for (i = 1; i < kbr->max_db; i++)
        {
          rc = try_database_index (kbr, i);
          if (rc == 0)
            break;
        }
    }

  /* No DB available, give up. */
  if (kbr->db == 0)
    {
      rc = -1;
      goto err_cleanup;
    }

  rep = redisCommand (ctx, "SELECT %u", kbr->db);
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_release_db (struct kb_redis *kbr)
{
  int rc;
  redisContext *ctx = kbr->rctx;
  redisReply *rep;

  if (ctx == NULL)
    return -EINVAL;

  rep = redisCommand (ctx, "SELECT 0"); /* Management database*/
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }
  freeReplyObject (rep);

  rep = redisCommand (ctx, "HDEL %s %d", GLOBAL_DBINDEX_NAME, kbr->db);
  if (rep == NULL || rep->type != REDIS_REPLY_INTEGER)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static redisContext *
get_redis_ctx (struct kb_redis *kbr)
{
  int rc;

  if (kbr->rctx != NULL)
    return kbr->rctx;

  do
    {
      kbr->rctx = redisConnectUnix (kbr->path);
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error: %s", __func__,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          return NULL;
        }

      rc = select_database (kbr);
      if (rc)
        {
          g_debug ("%s: No redis DB available, retrying in %ds...", __func__,
                   KB_RETRY_DELAY);
          sleep (KB_RETRY_DELAY);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
        }
    }
  while (rc != 0);

  g_debug ("%s: connected to redis://%s/%d", __func__, kbr->path, kbr->db);
  return kbr->rctx;
}

static int
redis_test_connection (struct kb_redis *kbr)
{
  int rc = 0;
  redisReply *rep;

  rep = redis_cmd (kbr, "PING");
  if (rep == NULL)
    {
      /* not 100% relevant but hiredis doesn't provide us with proper error
       * codes. */
      rc = -ECONNREFUSED;
      goto out;
    }

  if (rep->type != REDIS_REPLY_STATUS)
    {
      rc = -EINVAL;
      goto out;
    }

  if (g_ascii_strcasecmp (rep->str, "PONG"))
    {
      rc = -EPROTO;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_delete (kb_t kb)
{
  struct kb_redis *kbr;

  kbr = redis_kb (kb);

  redis_delete_all (kbr);
  redis_release_db (kbr);

  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  g_free (kb);
  return 0;
}

static int
redis_new (kb_t *kb, const char *kb_path)
{
  struct kb_redis *kbr;
  int rc = 0;

  kbr = g_malloc0 (sizeof (struct kb_redis) + strlen (kb_path) + 1);
  kbr->kb.kb_ops = &KBRedisOperations;
  strcpy (kbr->path, kb_path);

  rc = redis_test_connection (kbr);
  if (rc)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: cannot access redis at '%s'", __func__,  kb_path);
      redis_delete ((kb_t)kbr);
      kbr = NULL;
    }

  *kb = (kb_t)kbr;

  return rc;
}

static kb_t
redis_find (const char *kb_path, const char *key)
{
  struct kb_redis *kbr;
  unsigned int i = 1;
  redisReply *rep;

  kbr = g_malloc0 (sizeof (struct kb_redis) + strlen (kb_path) + 1);
  kbr->kb.kb_ops = &KBRedisOperations;
  strncpy (kbr->path, kb_path, strlen (kb_path));

  do
    {
      kbr->rctx = redisConnectUnix (kbr->path);
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error: %s", __func__,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          g_free (kbr);
          return NULL;
        }

      kbr->db = i;
      rep = redisCommand (kbr->rctx, "HEXISTS %s %d", GLOBAL_DBINDEX_NAME, i);
      if (rep == NULL || rep->type != REDIS_REPLY_INTEGER || rep->integer != 1)
        {
          if (rep != NULL)
            freeReplyObject (rep);
          i++;
          continue;
        }
      freeReplyObject (rep);
      rep = redisCommand (kbr->rctx, "SELECT %u", i);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        {
          sleep (KB_RETRY_DELAY);
          kbr->rctx = NULL;
        }
      else
        {
          freeReplyObject (rep);
          if (key && kb_item_get_int (&kbr->kb, key) > 0)
            return (kb_t) kbr;
        }
      redisFree (kbr->rctx);
      i++;
    }
  while (i < kbr->max_db);

  return NULL;
}

void
kb_item_free (struct kb_item *item)
{
  while (item != NULL)
    {
      struct kb_item *next;

      next = item->next;
      if (item->type == KB_TYPE_STR && item->v_str != NULL)
        g_free (item->v_str);
      g_free (item);
      item = next;
    }
}

static int
redis_transaction_new (struct kb_redis *kbr, struct redis_tx *rtx)
{
  int rc = 0;
  redisContext *ctx;
  redisReply *rep = NULL;

  rtx->kbr = kbr;
  rtx->valid = false;

  /* That is the quick, dirty & easy way to guarantee a fresh connection */
  redis_lnk_reset ((kb_t)kbr);

  ctx = get_redis_ctx (kbr);
  if (ctx == NULL)
    return -1;

  rep = redisCommand (ctx, "MULTI");
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rtx->valid = true;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_transaction_cmd (struct redis_tx *rtx, const char *fmt, ...)
{
  int rc = 0;
  va_list ap;
  redisReply *rep;

  if (!rtx->valid)
    return -1;

  va_start (ap, fmt);

  rep = redisvCommand (rtx->kbr->rctx, fmt, ap);
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

err_cleanup:
  va_end (ap);

  if (rc)
    rtx->valid = false;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_transaction_end (struct redis_tx *rtx, redisReply **rep)
{
  int rc;
  redisReply *preply;

  preply = NULL;

  if (!rtx->valid)
    return -1;

  preply = redisCommand (rtx->kbr->rctx, "EXEC");
  if (preply == NULL || preply->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto err_cleanup;
    }

  *rep = preply;
  rc = 0;

err_cleanup:

  if (rc)
    {
      freeReplyObject (preply);
      *rep = NULL;
    }

  memset (rtx, 0, sizeof (struct redis_tx));

  return rc;
}

static struct kb_item *
redis2kbitem_single (const char *name, const redisReply *elt, int force_int)
{
  struct kb_item *item;
  size_t namelen;

  if (elt->type != REDIS_REPLY_STRING && elt->type != REDIS_REPLY_INTEGER)
    return NULL;

  namelen = strlen (name) + 1;

  item = g_malloc0 (sizeof (struct kb_item) + namelen);
  if (elt->type == REDIS_REPLY_INTEGER)
    {
      item->type  = KB_TYPE_INT;
      item->v_int = elt->integer;
    }
  else if (force_int)
    {
      item->type  = KB_TYPE_INT;
      item->v_int = atoi (elt->str);
    }
  else
    {
      item->type  = KB_TYPE_STR;
      item->v_str = g_strdup (elt->str);
    }

  item->next    = NULL;
  item->namelen = namelen;
  strcpy (item->name, name);

  return item;
}

static struct kb_item *
redis2kbitem (const char *name, const redisReply *rep)
{
  struct kb_item *kbi;

  kbi = NULL;

  switch (rep->type)
    {
      unsigned int i;

      case REDIS_REPLY_STRING:
      case REDIS_REPLY_INTEGER:
        kbi = redis2kbitem_single (name, rep, 0);
        break;

      case REDIS_REPLY_ARRAY:
        for (i = 0; i < rep->elements; i++)
          {
            struct kb_item *tmpitem;

            tmpitem = redis2kbitem_single (name, rep->element[i], 0);
            if (tmpitem == NULL)
              break;

            if (kbi != NULL)
              {
                tmpitem->next = kbi;
                kbi = tmpitem;
              }
            else
              kbi = tmpitem;
          }
        break;

      case REDIS_REPLY_NIL:
      case REDIS_REPLY_STATUS:
      case REDIS_REPLY_ERROR:
      default:
        break;
    }

  return kbi;
}

static redisReply *
redis_cmd (struct kb_redis *kbr, const char *fmt, ...)
{
  redisReply *rep;
  va_list ap, aq;
  int retry = 0;

  va_start (ap, fmt);
  do
    {
      redisContext *ctx;

      rep = NULL;

      ctx = get_redis_ctx (kbr);
      if (ctx == NULL)
        {
          va_end (ap);
          return NULL;
        }

      va_copy (aq, ap);
      rep = redisvCommand (ctx, fmt, aq);
      va_end (aq);

      if (ctx->err)
        {
          if (rep != NULL)
            freeReplyObject (rep);

          redis_lnk_reset ((kb_t)kbr);
          retry = !retry;
        }
      else
        retry = 0;
    }
  while (retry);

  va_end (ap);

  return rep;
}

static struct kb_item *
redis_get_single (kb_t kb, const char *name, enum kb_item_type type)
{
  struct kb_item *kbi;
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = redis_kb (kb);
  kbi = NULL;

  rep = redis_cmd (kbr, "SRANDMEMBER %s", name);
  if (rep == NULL || rep->type != REDIS_REPLY_STRING)
    {
      kbi = NULL;
      goto out;
    }

  kbi = redis2kbitem_single (name, rep, type == KB_TYPE_INT);

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return kbi;
}

static char *
redis_get_str (kb_t kb, const char *name)
{
  struct kb_item *kbi;

  kbi = redis_get_single (kb, name, KB_TYPE_STR);
  if (kbi != NULL)
    {
      char *res;

      res = kbi->v_str;
      kbi->v_str = NULL;
      kb_item_free (kbi);
      return res;
    }
  return NULL;
}

static int
redis_get_int (kb_t kb, const char *name)
{
  struct kb_item *kbi;

  kbi = redis_get_single (kb, name, KB_TYPE_INT);
  if (kbi != NULL)
    {
      int res;

      res = kbi->v_int;
      kb_item_free (kbi);
      return res;
    }
  return -1;
}

static char *
redis_get_nvt (kb_t kb, const char *oid, enum kb_nvt_pos position)
{
  struct kb_redis *kbr;
  redisReply *rep;
  char *res = NULL;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "LINDEX nvt:%s %d", oid, position);
  if (!rep)
    return NULL;
  if (rep->type == REDIS_REPLY_INTEGER)
    res = g_strdup_printf ("%lld", rep->integer);
  else if (rep->type == REDIS_REPLY_STRING)
    res = g_strdup (rep->str);
  freeReplyObject (rep);

  return res;
}

static struct kb_item *
redis_get_all (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  struct kb_item *kbi;
  redisReply *rep;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "SMEMBERS %s", name);
  if (rep == NULL)
    return NULL;

  kbi = redis2kbitem (name, rep);

  freeReplyObject (rep);

  return kbi;
}

static struct kb_item *
redis_get_pattern (kb_t kb, const char *pattern)
{
  struct kb_redis *kbr;
  struct kb_item *kbi;
  redisReply *rep;
  unsigned int i;

  kbr = redis_kb (kb);
  kbi = NULL;

  rep = redis_cmd (kbr, "KEYS %s", pattern);
  if (rep == NULL)
    return NULL;

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return NULL;
    }

  for (i = 0; i < rep->elements; i++)
    {
      const char *key;
      struct kb_item *tmp;
      redisReply *rep_range;

      key = rep->element[i]->str;

      rep_range = redis_cmd (kbr, "SMEMBERS %s", key);
      if (rep_range == NULL)
        continue;

      tmp = redis2kbitem (key, rep_range);
      if (tmp == NULL)
        goto next; /* race condition, bah... */

      if (kbi != NULL)
        {
          struct kb_item *tmp2;

          tmp2 = tmp;
          while (tmp->next != NULL)
            tmp = tmp->next;

          tmp->next = kbi;
          kbi = tmp2;
        }
      else
        kbi = tmp;

next:
      if (rep_range != NULL)
        freeReplyObject (rep_range);
    }

  freeReplyObject (rep);

  return kbi;
}

static int
redis_del_items (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "DEL %s", name);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_add_str (kb_t kb, const char *name, const char *str)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "SADD %s %s", name, str);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_set_str (kb_t kb, const char *name, const char *val)
{
  struct kb_redis *kbr;
  struct redis_tx rtx;
  redisReply *rep;
  int rc;

  kbr = redis_kb (kb);
  rep = NULL;

  rc = redis_transaction_new (kbr, &rtx);
  if (rc)
    {
      rc = -1;
      goto out;
    }

  redis_transaction_cmd (&rtx, "DEL %s", name);
  redis_transaction_cmd (&rtx, "SADD %s %s", name, val);

  rc = redis_transaction_end (&rtx, &rep);
  if (rc || rep == NULL || rep->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_add_int (kb_t kb, const char *name, int val)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "SADD %s %d", name, val);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_set_int (kb_t kb, const char *name, int val)
{
  struct kb_redis *kbr;
  struct redis_tx rtx;
  redisReply *rep;
  int rc;

  kbr = redis_kb (kb);
  rep = NULL;

  rc = redis_transaction_new (kbr, &rtx);
  if (rc)
    {
      rc = -1;
      goto out;
    }

  redis_transaction_cmd (&rtx, "DEL %s", name);
  redis_transaction_cmd (&rtx, "SADD %s %d", name, val);

  rc = redis_transaction_end (&rtx, &rep);
  if (rc || rep == NULL || rep->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_add_nvt (kb_t kb, const nvti_t *nvt, const char *filename)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;

  if (!nvt || !filename)
    return -1;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr,
                   "RPUSH nvt:%s %s %s %s %s %s %s %s %s %s %s %s %d %d %s %s"
                   " %s %s",
                   nvti_oid (nvt), filename, nvti_required_keys (nvt) ?: "",
                   nvti_mandatory_keys (nvt) ?: "",
                   nvti_excluded_keys (nvt) ?: "",
                   nvti_required_udp_ports (nvt) ?: "",
                   nvti_required_keys (nvt) ?: "",
                   nvti_dependencies (nvt) ?: "", nvti_tag (nvt) ?: "",
                   nvti_cve (nvt) ?: "", nvti_bid (nvt) ?: "",
                   nvti_xref (nvt) ?: "", nvti_category (nvt),
                   nvti_timeout (nvt), nvti_family (nvt), nvti_copyright (nvt),
                   nvti_name (nvt), nvti_version (nvt));
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep != NULL)
    freeReplyObject (rep);

  rep = redis_cmd (kbr, "SADD filename:%s:oid %s", filename, nvti_oid (nvt));
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static int
redis_lnk_reset (kb_t kb)
{
  struct kb_redis *kbr;

  kbr = redis_kb (kb);

  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  return 0;
}

static int
redis_flush_all (kb_t kb, const char *except)
{
  unsigned int i = 1;
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = redis_kb (kb);
  if (kbr->rctx)
    redisFree (kbr->rctx);

  g_debug ("%s: deleting all DBs at %s except %s", __func__, kbr->path, except);
  do
    {
      kbr->rctx = redisConnectUnix (kbr->path);
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error: %s", __func__,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          return -1;
        }

      kbr->db = i;
      rep = redisCommand (kbr->rctx, "HEXISTS %s %d", GLOBAL_DBINDEX_NAME, i);
      if (rep == NULL || rep->type != REDIS_REPLY_INTEGER || rep->integer != 1)
        {
          freeReplyObject (rep);
          redisFree (kbr->rctx);
          i++;
          continue;
        }
      freeReplyObject (rep);
      rep = redisCommand (kbr->rctx, "SELECT %u", i);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        {
          freeReplyObject (rep);
          sleep (KB_RETRY_DELAY);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
        }
      else
        {
          freeReplyObject (rep);
          /* Don't remove DB if it has "except" key. */
          if (except && kb_item_get_int (kb, except) > 0)
            {
              i++;
              redisFree (kbr->rctx);
              continue;
            }
          redis_delete_all (kbr);
          redis_release_db (kbr);
          redisFree (kbr->rctx);
        }
      i++;
    }
  while (i < kbr->max_db);

  g_free (kb);
  return 0;
}

int
redis_delete_all (struct kb_redis *kbr)
{
  int rc;
  redisReply *rep;
  struct sigaction new_action, original_action;

  /* Ignore SIGPIPE, in case of a lost connection. */
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

  g_debug ("%s: deleting all elements from KB #%u", __func__, kbr->db);
  rep = redis_cmd (kbr, "FLUSHDB");
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (sigaction (SIGPIPE, &original_action, NULL))
    return -1;
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}


static const struct kb_operations KBRedisOperations = {
  .kb_new          = redis_new,
  .kb_find         = redis_find,
  .kb_delete       = redis_delete,
  .kb_get_single   = redis_get_single,
  .kb_get_str      = redis_get_str,
  .kb_get_int      = redis_get_int,
  .kb_get_nvt      = redis_get_nvt,
  .kb_get_all      = redis_get_all,
  .kb_get_pattern  = redis_get_pattern,
  .kb_add_str      = redis_add_str,
  .kb_set_str      = redis_set_str,
  .kb_add_int      = redis_add_int,
  .kb_set_int      = redis_set_int,
  .kb_add_nvt      = redis_add_nvt,
  .kb_del_items    = redis_del_items,
  .kb_lnk_reset    = redis_lnk_reset,
  .kb_flush        = redis_flush_all,
};

const struct kb_operations *KBDefaultOperations = &KBRedisOperations;
