#ifndef __NESSUS_DATA_H__
#define __NESSUS_DATA_H__



#define DATA_INT    1
#define DATA_STR    2
#define DATA_BLOB   3
#define DATA_PTR    4
#define DATA_DATA   5





struct elem {
	char * name;
	int size;
	int type;
	union {
	  int v_int;
	  char* v_str;
	  unsigned char* v_blob;
	  void* v_ptr;
	  struct data * v_data;
	  }v;
	struct elem * next;
};


struct data {
	struct elem * list;
	
	int walktype;
	struct elem * current;
};

struct data * data_init();
int data_add_str (struct data*, char*, char*);
int data_add_blob(struct data*, char*, u_char *, int);
int data_add_int (struct data*, char*, int);
int data_add_ptr (struct data*, char*, void*);
int data_add_data(struct data*, char*, struct data*);


int data_get_int (struct data*, char*, int*);
int data_get_str (struct data*, char*, char**);
int data_get_blob(struct data*, char*, u_char**);
int data_get_ptr (struct data*, char* , void**);
int data_get_data(struct data*, char*, struct data**);


int data_set_int(struct data*, char*, int);
int data_set_str(struct data*, char*, char*);
int data_set_blob(struct data*, char*, u_char*, int);
int data_set_ptr(struct data*, char*, void*);
int data_set_data(struct data*, char*, struct data*);

int data_addset_int(struct data*, char*, int);
int data_addset_str(struct data*, char*, char*);
int data_addset_blob(struct data*, char*, u_char*, int);
int data_addset_ptr(struct data*, char*, void*);
int data_addset_data(struct data*, char*, struct data*);

int data_get_size(struct data*, char*, int*);
int data_get_type(struct data*, char*, int*);

int data_free(struct data*);
int data_free_all(struct data*);

int data_walk_init(struct data*);
int data_walk_next_str(struct data*, char **, char**);
int data_walk_next_int(struct data*, char**, int *);


struct data * data_copy(struct data *);
int data_dump(struct data*);

#endif
