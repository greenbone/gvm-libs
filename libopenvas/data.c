/*
 * data.c :
 * 	Primitives for an opaque data storage struct which is bound to
 * 	eventually replace the arglists and harglsts
 *
 * The advantages of this structure compared to the arglists are :
 *
 * 	- Data is typed. We won't mistake a pointer for an int and vice versa
 * 	- Memory is managed. This means that strings are actually copied in
 * 	  the structure, not just their address. This caused a lot of problems
 * 	  with the arglists
 * 	- No ambiguity when fetching data. There were problems with the arglists
 * 	  where we would do an arg_get_value("foo"), obtain 0 as a result
 * 	  and could not differenciate that from an error or the fact that foo
 * 	  is actually equal to zero
 * 	- Full opacity. This will allow us to move to a more suited data
 * 	  structure in the future (probably hash table)
 */
#include <includes.h>
#include "data.h"



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
	};

static struct name_cache *cache = NULL;


static struct name_cache * 
cache_get_name(name)
 char * name;
{
 struct name_cache * nc = cache;
 
 if(name == NULL)
  return NULL;
  
 while(nc != NULL)
 {
  if(nc->name != NULL && strcmp(nc->name, name) == 0 )
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
 struct name_cache * nc = cache;
 while(nc != NULL)
 {
  if(nc->name == NULL)
    break;
  else 
    nc = nc->next;
 }
 
 
 if(nc == NULL)
 {
  nc = malloc(sizeof(struct name_cache));
  nc->next = cache;
  cache = nc;
 }
 
 nc->name = strdup(name);
 nc->occurences = 1;
 return nc;
}

static char *
cache_inc(name)
 char * name;
{
 struct name_cache * nc = cache_get_name(name);
 if(nc)
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

 if(name == NULL)
  return;

 nc  = cache_get_name(name);
 if(nc == NULL)
 {
  /*
  fprintf(stderr, "libnessus: cache_dec(): non-existant name\n");
  */
  return;
 }
 
 nc->occurences --;
 if(nc->occurences == 0)
 {
   if(nc->name == name)
   {
#ifdef DEBUG
    memset(nc->name, 'X', strlen(nc->name));
#endif   
    free(nc->name);
    nc->name = NULL;
   }
   else 
    fprintf(stderr, "libnessus: cache_dec(): invalid ptr\n");
  }
}

/*----------------------------------------------------------------------------*/

struct data * data_init()
{
 struct data *data = malloc(sizeof(struct data));
 data->list = data->current = NULL;
 return data;
}


int data_add_str(struct data * data, char* name, char * str)
{
 int len;
 struct elem * elem;
 
 if(data == NULL)
  return -1;
  
 if(str == NULL)
  return -1; /* Or shall have an empty entry ? XXX */
 
 len = strlen(str);
 elem = malloc(sizeof(struct elem));
 
 elem->name = cache_inc(name);
 elem->size = len + 1;
 elem->type = DATA_STR;
 elem->v.v_str = strdup(str);
 elem->next = data->list;
 data->list = elem;
 return 0;
}

int data_add_blob(struct data * data, char* name, u_char * blob, int len)
{
 struct elem * elem;
 
 if(data == NULL)
  return -1;
  
 if(blob == NULL)
  return -1; /* Or shall have an empty entry ? XXX */
 
 elem = malloc(sizeof(struct elem));
 
 elem->name = cache_inc(name);
 elem->size = len + 1;
 elem->type = DATA_BLOB;
 elem->v.v_blob = malloc(len);
 memcpy(elem->v.v_blob, blob, len);
 elem->next = data->list;
 data->list = elem;
 return 0;
}



int data_add_int(struct data * data, char * name, int value)
{
 struct elem * elem;
 
 if(data == NULL)
  return -1;
  
 elem = malloc(sizeof(struct elem));
 
 elem->name = cache_inc(name);
 elem->size = 0;
 elem->type = DATA_INT;
 elem->v.v_int = value;
 elem->next = data->list;
 data->list = elem;
 return 0;
}

int data_add_ptr(struct data * data, char * name, void * ptr)
{
 struct elem * elem;
 
 if(data == NULL)
  return -1;
 
 elem = malloc(sizeof(struct elem));
 
 elem->name = cache_inc(name);
 elem->size = 0;
 elem->type = DATA_PTR;
 elem->v.v_ptr = ptr;
 elem->next = data->list;
 data->list = elem;
 return 0;
}

int data_add_data(struct data * data, char * name, struct data * val)
{
 struct elem * elem;
 
 if(data == NULL)
  return -1;
 
 elem = malloc(sizeof(struct elem));
 
 elem->name = cache_inc(name);
 elem->size = 0;
 elem->type = DATA_DATA;
 elem->v.v_data = data_copy(val);
 elem->next = data->list;
 data->list = elem;
 return 0;
}




static struct elem * elem_search(struct elem * elem, char * name, int type)
{
 while(elem != NULL)
 {
  if((type == 0 || elem->type == type)  && strcmp(elem->name, name) == 0)
   return elem;
  else
   elem = elem->next;
 }
 return NULL;
}

int data_get_int(struct data * data, char * name, int * value)
{
 struct elem * e;
 if(data == NULL || 
    name == NULL || 
    value == NULL)
  return -1;
  
 e = elem_search(data->list, name, DATA_INT);
 if(e == NULL)
  return 1;
  
 *value = e->v.v_int;
  return 0;
}


int data_get_str(struct data * data, char * name, char ** value)
{
 struct elem * e;
 if(data == NULL || 
    name == NULL || 
    value == NULL)
  return -1;
  
 e = elem_search(data->list, name, DATA_STR);
 if(e == NULL)
  return 1;
  
 *value = e->v.v_str;
 return 0;
}

int data_get_blob(struct data * data, char * name, u_char ** value)
{
 struct elem * e;
 if(data == NULL || 
    name == NULL || 
    value == NULL)
  return -1;
  
 e = elem_search(data->list, name, DATA_BLOB);
 if(e == NULL)
  return 1;
  
 *value = e->v.v_blob;
  return 0;
}

int data_get_ptr(struct data * data, char * name, void ** value)
{
 struct elem * e;
 if(data == NULL || 
    name == NULL || 
    value == NULL)
  return -1;
  
 e = elem_search(data->list, name, DATA_PTR);
 if(e == NULL)
  return 1;
  
 *value = e->v.v_ptr;
 return 0;
}

int data_get_data(struct data * data, char * name, struct data ** value)
{
 struct elem * e;
 if(data == NULL || 
    name == NULL || 
    value == NULL)
  return -1;
  
 e = elem_search(data->list, name, DATA_DATA);
 if(e == NULL)
  return 1;
  
 *value = e->v.v_data;
 return 0;
}


int data_set_int(struct data * data, char * name, int value)
{
  struct elem * e;
  if(data == NULL || 
     name == NULL)
    return -1;
 
  e = elem_search(data->list, name, DATA_INT);
  if(e == NULL)
    return 1;
  e->v.v_int = value;
  return 0;
}


int data_set_str(struct data * data, char * name, char * value)
{
  struct elem * e;
  if(data == NULL || 
     name == NULL)
    return -1;
 
  e = elem_search(data->list, name, DATA_STR);
  if(e == NULL)
    return 1;
  free(e->v.v_str);
  e->size = strlen(value) + 1;
  e->v.v_str = estrdup(value);
  return 0;
}

int data_set_ptr(struct data * data, char * name, void * value)
{
  struct elem * e;
  if(data == NULL || 
     name == NULL)
    return -1;
 
  e = elem_search(data->list, name, DATA_PTR);
  if(e == NULL)
    return 1;
  e->v.v_ptr = value;
  return 0;
}

int data_set_blob(struct data * data, char * name, u_char * value, int sz)
{
 struct elem * e;
  if(data == NULL || 
     name == NULL)
    return -1;
 
  e = elem_search(data->list, name, DATA_BLOB);
  if(e == NULL)
    return 1;
  free(e->v.v_blob);
  e->size = sz;
  e->v.v_blob = malloc(sz);
  memcpy(e->v.v_blob, value, sz);
  return 0;
}

int data_set_data(struct data * data, char * name, struct data * value)
{
  struct elem * e;

  if(data == NULL || 
     name == NULL)
    return -1;
 
  e = elem_search(data->list, name, DATA_DATA);
  if(e == NULL)
    return 1;
    data_free(e->v.v_data);
    e->v.v_data = data_copy(value);
  return 0;
}


int data_addset_int(struct data * data, char * name, int value)
{
 int old;
 if(data_get_int(data, name, &old) != 0)
  return data_set_int(data, name, value);
 else
  return data_add_int(data, name, value);
}

int data_addset_str(struct data * data, char * name, char * value)
{
 char * old;
 if(data_get_str(data, name, &old) != 0)
  return data_set_str(data, name, value);
 else
  return data_add_str(data, name, value);
}

int data_addset_ptr(struct data * data, char * name, void * value)
{
 void * old;
 if(data_get_ptr(data, name, &old) != 0)
  return data_set_ptr(data, name, value);
 else
  return data_add_ptr(data, name, value);
}

int data_addset_blob(struct data * data, char * name, u_char * value, size_t sz)
{
 u_char * old;
 if(data_get_blob(data, name, &old) != 0)
  return data_set_blob(data, name, value, sz);
 else
  return data_add_blob(data, name, value, sz);
}

int data_addset_data(struct data * data, char * name, struct data * value)
{
 struct data * old;
 if(data_get_data(data, name, &old) != 0)
  return data_set_data(data, name, value);
 else
  return data_add_data(data, name, value);
}



int data_get_size(struct data * data, char * name, int * size)
{
 struct elem * e;
 if(data == NULL || name == NULL || size == NULL)
  return -1;
 
 e = elem_search(data->list, name, 0);
 if(e == NULL)
  return 1;
 *size = e->size;
 return 0;
}


int data_get_type(struct data * data, char * name, int * type)
{
  struct elem * e;
 if(data == NULL || name == NULL || type == NULL)
  return -1;
 
 e = elem_search(data->list, name, 0);
 if(e == NULL)
  return 1;
 *type = e->type;
 return 0;
}


struct data * data_copy(struct data * data)
{
  struct data * cop;
  struct elem * e;
  if( data == NULL )
    return NULL;

  cop = data_init();
  cop->walktype = data->walktype;
  e = data->list;
  while ( e != NULL )
    {
      switch(e->type)
	{
	case DATA_INT:
	  data_add_int(cop, e->name, e->v.v_int);
	  break;
	case DATA_STR:
	  data_add_str(cop, e->name, e->v.v_str);
	  break;
	case DATA_PTR:
	  data_add_ptr(cop, e->name, e->v.v_ptr);
	  break;
	case DATA_BLOB:
	  data_add_blob(cop, e->name, e->v.v_blob, e->size);
	  break;
	case DATA_DATA:
	  data_add_data(cop, e->name, e->v.v_data);
	  break;
	}
      e = e->next;
    }
  cop->current = NULL;
  return cop;
}

int data_free(struct data * data)
{
 struct elem * e = data->list;
 while ( e != NULL )
 {
  struct elem * nxt;
  if(e->type == DATA_BLOB)
   free(e->v.v_blob);
  if(e->type == DATA_STR)
   free(e->v.v_str);
  nxt = e->next;
  cache_dec(e->name);
  free(e);
  e = nxt;
 }
 return 0;
}


int data_free_all(struct data * data)
{
 struct elem * e = data->list;
 while ( e != NULL )
 {
  struct elem * nxt;
  if(e->type == DATA_BLOB)
   free(e->v.v_blob);
  if(e->type == DATA_STR)
   free(e->v.v_str);
  if(e->type == DATA_DATA)
   data_free_all(e->v.v_data);
  nxt = e->next;
  cache_dec(e->name);
  free(e);
  e = nxt;
 }
 free(data);
 return 0;
}



int data_walk_init(struct data * data)
{
  if(data == NULL)
    return -1;

 data->current = data->list;

 return 0;
}

static struct elem * data_walk_next(struct data * data)
{
 if(data->current == NULL)
  return NULL;
 else
 {
  struct elem  * ret;
  ret = data->current;
  data->current = data->current->next;
  return ret;
 }
}

int data_walk_next_str(struct data * data, char ** name, char ** value)
{
 struct elem * e;
 
 for(;;)
 {
 e = data_walk_next(data);
 if(e == NULL)
  return -1;
 if(e->type == DATA_STR)
  {
   if(name) 
    *name = e->name;
   if(value)
    *value = e->v.v_str;
   return 0;
  }
 }
}

int data_walk_next_int(struct data * data, char ** name, int * value)
{
 struct elem * e;
 
 for(;;)
 {
 e = data_walk_next(data);
 if(e == NULL)
  return -1;
 if(e->type == DATA_INT)
  {
   if(name) 
    *name = e->name;
   if(value)
    *value = e->v.v_int;
   return 0;
  }
 }
}

int data_walk_next_ptr(struct data * data, char ** name, void ** value)
{
 struct elem * e;
 
 for(;;)
 {
 e = data_walk_next(data);
 if(e == NULL)
  return -1;
 if(e->type == DATA_PTR)
  {
   if(name) 
    *name = e->name;
   if(value)
    *value = e->v.v_ptr;
   return 0;
  }
 }
}


int data_walk_next_blob(struct data * data, char ** name, u_char ** value)
{
 struct elem * e;
 
 for(;;)
 {
 e = data_walk_next(data);
 if(e == NULL)
  return -1;
 if(e->type == DATA_BLOB)
  {
   if(name) 
    *name = e->name;
   if(value)
    *value = e->v.v_blob;
   return 0;
  }
 }
}

int data_walk_next_data(struct data * data, char ** name, struct data **value)
{
 struct elem * e;
 
 for(;;)
 {
 e = data_walk_next(data);
 if(e == NULL)
  return -1;
 if(e->type == DATA_DATA)
  {
   if(name) 
    *name = e->name;
   if(value)
    *value = e->v.v_data;
   return 0;
  }
 }
}


static void printspc(int level)
{
  while(level != 0)
    {
      printf(" ");level--;
    }
}
static int _data_dump(struct data * data, int level)
{
  struct elem * e;
  if(data == NULL)
    return 0;

  e = data->list;

  while(e != NULL)
    {
      switch(e->type)
	{
	case DATA_INT:
	  printspc(level);
	  printf("[int] %s->%d\n",e->name, e->v.v_int);
	  break;
	case DATA_STR:
	  printspc(level);
	  printf("[str] %s->'%s'\n",e->name, e->v.v_str);
	  break;
	case DATA_BLOB:
	  printspc(level);
	  printf("[blob] %s->0x%x\n",e->name, (int)e->v.v_blob);
	  break;
	case DATA_PTR:
	  printspc(level);
	  printf("[ptr] %s->0x%x\n", e->name, (int)e->v.v_ptr);
	  break;
	case DATA_DATA:
	  printspc(level);
	  printf("[data] %s : \n", e->name);
	  _data_dump(e->v.v_data, level + 1);
	  break;
	}
      e = e->next;
    }
  return 0;
}

int data_dump(struct data * data)
{
  return _data_dump(data, 0);
}
 
