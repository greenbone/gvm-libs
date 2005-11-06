/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 - 2003 Renaud Deraison
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
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * 
 * Knowledge base management API
 */ 

#include <includes.h>
#define HASH_MAX 65537 



static unsigned int mkkey(char * name )
{
 char * p;
 unsigned int h = 0;

 if ( name == NULL )
	return 0;

 for ( p = name ; *p != '\0' ; p ++ )
  h = (h << 3) + (unsigned char)*p;


 return h % HASH_MAX;
}



struct kb_item ** kb_new()
{
 return emalloc(HASH_MAX * sizeof(struct kb_item*));
}


/*
 * READ the knowledge base
 */
struct kb_item * kb_item_get_single(struct kb_item ** kb, char * name, int type)
{
 unsigned int h = mkkey(name);
 struct kb_item * ret;
 
 if ( kb == NULL || name == NULL ) return NULL;
 
 
 ret = kb[h];
 while ( ret != NULL )
 {
  if( (strcmp(ret->name, name) == 0) && (type == 0 || (ret->type == type)) ) return ret;
  ret = ret->next;
 }
 
 return ret;
}



char * kb_item_get_str(struct kb_item ** kb, char * name)
{
 struct kb_item * item = kb_item_get_single(kb, name, KB_TYPE_STR);

 if(item == NULL) 
	return NULL;
 else 
	return item->v.v_str;
}

int kb_item_get_int(struct kb_item ** kb, char * name)
{
 struct kb_item * item = kb_item_get_single(kb, name, KB_TYPE_INT);
 if(item == NULL) 
	return -1;
 else 
	return item->v.v_int;
}


struct kb_item * kb_item_get_all(struct kb_item ** kb, char * name)
{
 unsigned h = mkkey(name);
 struct kb_item * k;
 struct kb_item *ret = NULL;
 
 if ( kb == NULL || name ==  NULL) 
    return NULL;
    
 k = kb[h];
 while ( k != NULL )
 {
  if( strcmp(k->name, name) == 0 ) 
        {
        struct kb_item * p;
        
        p = emalloc(sizeof(struct kb_item));
        memcpy(p, k, sizeof(struct kb_item));
        p->next = ret;
        ret = p;
        }
        k = k->next;
 }
 return ret;
}

struct kb_item * kb_item_get_pattern(struct kb_item ** kb, char * expr )
{
 int i;
 struct kb_item * k;
 struct kb_item * ret = NULL;
 
 if ( kb == NULL )
    return NULL;
 
 for ( i = 0 ; i < HASH_MAX ; i ++ )
 {
  k = kb[i];
  while ( k != NULL )
  {
   if( fnmatch(expr, k->name, 0) == 0)
   {
    struct kb_item * p;
    p = emalloc(sizeof(struct kb_item));
    memcpy(p, k, sizeof(struct kb_item));
    p->next = ret;
    ret = p;
   }
   k = k->next;
   }
  }
  return ret;
}
 


/* Free the result of kb_item_get_all() */
void kb_item_get_all_free(struct kb_item * items)
{
 while ( items != NULL )
 {
  struct kb_item * next;
  next = items->next;
  memset(items, 0xd7, sizeof(struct kb_item));
  efree(&items);
  items = next;
 }
}


/*
 * WRITE to the knowledge base
 */
 
 
 
static int kb_item_addset_str(struct kb_item ** kb, char * name, char * value, int replace)
{
 /* 
  * Before we write anything to the KB, we need to make sure that the same
  * (name,value) pair is not present already
  */
  int h = mkkey(name);
  struct kb_item * item;
  
  if ( kb == NULL )
    return -1;
   
  item = kb[h];

  while ( item != NULL )
  {
   if ( strcmp(item->name, name) == 0 )
   {
   if(item->type == KB_TYPE_STR 	    && 
      strcmp(item->v.v_str, value) == 0)
	return -1;

    if ( replace != 0 )
    {
    if ( item->type == KB_TYPE_STR )
	efree(&item->v.v_str);
   
    item->type = KB_TYPE_STR;
    item->v.v_str = estrdup(value);
    return 0;
    }
   }
   
   item = item->next;
  }

 item = emalloc(sizeof(struct kb_item));
 item->name = estrdup(name);
 item->v.v_str = estrdup(value);
 item->type = KB_TYPE_STR;
 item->next = kb[h];
 kb[h] = item;
 return 0;
}

int kb_item_add_str(struct kb_item ** kb, char * name, char * value)
{
 return kb_item_addset_str(kb, name, value, 0); 
}

int kb_item_set_str(struct kb_item ** kb, char * name, char * value)
{
 return kb_item_addset_str(kb, name, value, 1); 
}

/* Replace an old value in the KB by a new one */

static int kb_item_addset_int(struct kb_item ** kb, char * name, int value, int replace)
{
 /* 
  * Before we write anything to the KB, we need to make sure that the same
  * (name,value) pair is not present already
  */
  int h = mkkey(name);
  struct kb_item * item;
  
  if ( kb == NULL )
    return -1;
    
   
  item  = kb[h];

  while ( item != NULL )
  {
   if ( strcmp(item->name, name) == 0 )
   {
    if(item->type == KB_TYPE_INT 	    && 
      item->v.v_int == value)
	return -1;

    if ( replace != 0 )
    {
    if ( item->type == KB_TYPE_STR )
	efree(&item->v.v_str);
   
    item->type = KB_TYPE_INT;
    item->v.v_int = value;
    return 0;
    }
   }
    
   item = item->next;
  }

 item = emalloc(sizeof(struct kb_item));
 item->name = estrdup(name);
 item->v.v_int = value;
 item->type = KB_TYPE_INT;
 item->next = kb[h];
 kb[h] = item;
 return 0;
}


int kb_item_set_int(struct kb_item ** kb, char * name, int value)
{
 return kb_item_addset_int(kb, name, value, 1);
}
   
int kb_item_add_int(struct kb_item ** kb, char * name, int value)
{
 return kb_item_addset_int(kb, name, value, 0);
}


void kb_item_rm_all(struct kb_item ** kb, char * name)
{
 int h = mkkey(name);
 struct kb_item * k, * prev = NULL;
 
 if ( kb == NULL )
    return;
    
 k = kb[h];
 while ( k != NULL )
 {
  if(strcmp(k->name, name) == 0)
  {
   struct kb_item * next;
   if(k->type == ARG_STRING)
    efree(&k->v.v_str);
   
   efree(&k->name);
   next = k->next; 
   efree(&k);
   if(prev != NULL) prev->next = next;
   else kb[h] = next;
   k = next; 
  }
  else {
    prev = k;
    k = k->next;
    }
 }
}


/*
 * Backward compatibilty 
 */

struct arglist * plug_get_oldstyle_kb(struct arglist * desc )
{
 struct kb_item ** kb = arg_get_value(desc, "key");
 struct arglist * ret;
 struct kb_item * k;
 int i;
 if ( kb == NULL )
	return NULL;

 ret = emalloc ( sizeof(struct arglist) );
 for ( i = 0 ; i < HASH_MAX ; i ++ )
 {
  k = kb[i];
  while ( k != NULL )
  {
  if ( k->type == KB_TYPE_INT )
	arg_add_value(ret, k->name, ARG_INT, -1, (void*)k->v.v_int);
  else if ( k->type == KB_TYPE_STR )
	arg_add_value(ret, k->name, ARG_STRING, strlen(k->v.v_str), estrdup(k->v.v_str));
   k = k->next;
  }
 }

 return ret;

}
