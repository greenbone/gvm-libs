#ifndef STORE_H
#define STORE_H

int store_save_init();
int store_save_end();
struct arglist * store_save_plugin(struct arglist * plugin, char * path);
char * store_fetch_path(struct arglist * desc);
char * store_fetch_oid(struct arglist *);
char * store_fetch_version(struct arglist * desc);
char * store_fetch_summary(struct arglist * desc);
char * store_fetch_description(struct arglist * desc);
int store_fetch_category(struct arglist * desc);
char * store_fetch_copyright(struct arglist * desc);
char * store_fetch_family(struct arglist * desc);
char * store_fetch_cve_id(struct arglist * desc);
char * store_fetch_bugtraq_id(struct arglist * desc);
char * store_fetch_xref(struct arglist * desc);
char * store_fetch_tag(struct arglist * desc);

#endif
