/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
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
 * Arglists management
 */

#define EXPORTING
#include <includes.h>

/* 
 * We use a hash of the argument name to speed up the lookups
 * when calling arg_get_value()
 */
#define HASH_MAX 2713
static int mkhash(const char * name)
{
 int h = 0;
 int i;
 
 for(i=0;name[i] != '\0';i++)
 {
  h = ((h * 128) + name[i]) % HASH_MAX;
 }
 return h;
}

/*
 * name_cache :
 * 
 * A lot of entries in our arglists have the same name.
 * We use a caching system to avoid to allocate twice the same name
 * 
 * This saves about 300Kb of memory, with minimal performance impact
 */
struct name_cache {
	char * name;
	int occurences;
	struct name_cache * next;
	struct name_cache * prev;
	};


static int cache_inited = 0;
static struct name_cache cache[HASH_MAX+1];


static void cache_init()
{
 int i;
 for(i=0;i<HASH_MAX+1;i++)
 	{
	bzero(&(cache[i]), sizeof(cache[i]));
	}
 cache_inited = 1;
}

static struct name_cache * 
cache_get_name(name)
 char * name;
{
 struct name_cache * nc;
 int h;
 
 if(cache_inited == 0)
 	cache_init();
	
 if(!name)
  return NULL;
  
 h = mkhash(name);

 nc = cache[h].next;
  
 while(nc != NULL)
 {
  if(nc->name != NULL && 
    !strcmp(nc->name, name))
    	return nc;
  else 
  	nc = nc->next;
 }
 return NULL;
}

static struct name_cache *
cache_add_name(name)
 char * name;
{
 struct name_cache * nc;

 int h;
 
 if(name == NULL)
  return NULL;
 
 
 h = mkhash(name);
 
 
 nc = emalloc(sizeof(struct name_cache));
 nc->next = cache[h].next;
 nc->prev = NULL;
 nc->name = estrdup(name);
 nc->occurences = 1;
 if ( cache[h].next != NULL )
  cache[h].next->prev = nc;
 
 cache[h].next = nc;
 
 return nc;
}

static char *
cache_inc(name)
 char * name;
{
 struct name_cache * nc = cache_get_name(name);
 if(nc != NULL)
  nc->occurences ++;
 else
   nc = cache_add_name(name);  
 return nc->name;
}

static void 
cache_dec(name)
 char * name;
{
 struct name_cache* nc;

 if(!name)
  return;

 nc  = cache_get_name(name);
 if( nc == NULL)
 {
  /*
  fprintf(stderr, "libnessus: cache_dec(): non-existant name\n");
  */
  return;
 }
 
 nc->occurences --;
 if( nc->occurences == 0 ){
 	 int h = mkhash(name);
 	 efree(&nc->name);
	 if(nc->next != NULL)
	  nc->next->prev = nc->prev;
	  
	 if(nc->prev != NULL)
	  nc->prev->next = nc->next;
	 else
	  cache[h].next = nc->next;
	 
	 efree(&nc);
	}
}




ExtFunc void 
arg_free_name(name)
 char * name;
{
 cache_dec(name);
}




 

ExtFunc void 
arg_add_value(arglst, name, type, length, value)
  struct arglist * arglst;
  const char * name;
  int type;
  long length;
  void * value;
{
	if(!arglst)return;
	while(arglst->next)arglst = arglst->next;
	
	if (type == ARG_STRUCT) {
    	 void* new_val = emalloc(length);
     	 memcpy(new_val, value, length);
    	 value = new_val;
   	}

	arglst->name = cache_inc(name);
	arglst->value = value;
	arglst->length = length;
	arglst->type = type;
	arglst->next = emalloc(sizeof(struct arglist));
	arglst->hash = mkhash(arglst->name);
}


static struct arglist * arg_get(struct arglist * arg, const char * name)
{
 int h = mkhash(name);
 if(arg == NULL)
  return NULL;
 
 while(arg->next != NULL)
 {
  if(arg->hash == h && strcmp(arg->name, name) == 0)
    return arg;
  else
   arg = arg->next;
 }
 return NULL;
}




ExtFunc int 
arg_set_value(arglst, name, length, value)
 struct arglist * arglst;
 const char * name;
 long length;
 void *value;
{
 
 if(name == NULL)
  return -1;
  
 arglst = arg_get(arglst, name);
  
  if(arglst != NULL)
    {
      if (arglst->type == ARG_STRUCT) {
	void* new_val = emalloc(length);
	if (arglst->value) efree(&arglst->value);
	memcpy(new_val, value, length);
	value = new_val;
      }
      arglst->value = value;
      arglst->length = length;
      return 0;
    }
  else return -1; 
}

ExtFunc int 
arg_set_type(arglst, name, type)
 struct arglist * arglst;
 const char * name;
 int type;
{
  arglst = arg_get(arglst, name);
  if(arglst == NULL)
   return -1;
   
  if (arglst->type == ARG_STRUCT  &&  type != ARG_STRUCT) {
    efree(&arglst->value);
  }
  arglst->type = type;
  return 0;
}
  
  
ExtFunc void * 
arg_get_value(args, name)
 struct arglist * args;
 const char * name;
{

  if(args == NULL)
   return NULL;
  
  args = arg_get(args, name);
  if(args == NULL)
   return NULL;
  else  
  return(args->value);
}


ExtFunc int 
arg_get_length(args,name)
 struct arglist * args;
 const char * name;
{
  args = arg_get(args, name);
  if(args != NULL)
    return(args->length);
  else 
    return 0;
}


ExtFunc int 
arg_get_type(args,name)
 struct arglist * args;
 const char * name;
{
 args = arg_get(args, name);
 if( args != NULL )
    return(args->type);
  else 
    return -1;
}


ExtFunc void arg_dup(dst, src)
 struct arglist * dst;
 struct arglist * src;
{
 if(!src)
  return;
  
 while(src->next)
 {
  dst->name = cache_inc(src->name);
  dst->type = src->type;
  dst->length = src->length;
  dst->hash = src->hash;
  switch(src->type)
  {
   case ARG_INT :
   case ARG_PTR : 
    dst->value = src->value;
    break;
    
   case ARG_STRING :
    if(src->value){
     dst->value = estrdup((char*)src->value);
    }
    break;
    
   case ARG_STRUCT :
     if (src->value) {
       dst->value = emalloc(src->length);
       memcpy(dst->value, src->value, src->length);
       dst->length = src->length;
     }
     break;

 
  case ARG_ARGLIST :
    dst->value = emalloc(sizeof(struct arglist));
    arg_dup((struct arglist *)dst->value, (struct arglist *)src->value);
    break;
  }
  dst->next = emalloc(sizeof(struct arglist));
  dst = dst->next;
  src = src->next;
 }
}


ExtFunc void 
arg_dump(args, level)
 struct arglist * args;
 int level;
{
	const char * spaces = "--------------------";
	if(!args)
	{
		printf("Error ! args == NULL\n");
		return;
	}
	
	if(args)
	 while(args->next)
	 {
		switch(args->type)
		{
			case ARG_STRING :
			
			fprintf(stderr, "%sargs->%s : %s\n",spaces+(20-level),
			args->name,
			(char *)args->value);
			break;
			case ARG_ARGLIST :
			
			fprintf(stderr, "%sargs->%s :\n", spaces+(20-level),
			args->name);
			arg_dump(args->value, level+1);
			break;
			case ARG_INT :
			fprintf(stderr, "%sargs->%s : %d\n",spaces+(20-level),
			args->name,
			(int)args->value);
			break;
			default :
			fprintf(stderr, "%sargs->%s : %d\n",spaces+(20-level),
			args->name,
			(int)args->value);
			break;
		}
		args = args->next;
	}
}


ExtFunc void
arg_free(arg)
 struct arglist* arg;
{
 while(arg)
 {
  struct arglist * next = arg->next;
  cache_dec(arg->name);
  efree(&arg);
  arg = next;
 }
}


ExtFunc void arg_free_all(arg)
 struct arglist* arg;
{
 while(arg)
 {
  struct arglist * next = arg->next;
  switch(arg->type)
  {
   case ARG_ARGLIST :
    arg_free_all(arg->value);
    break;
   case ARG_STRING :
    efree(&arg->value);
    break;
   case ARG_STRUCT :
    efree(&arg->value);
    break;
  }
  cache_dec(arg->name);
  efree(&arg);
  arg = next;
 }
}
