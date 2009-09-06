#ifndef STORE_H
#define STORE_H

struct arglist * store_save_plugin(struct arglist * plugin, char * path);
char * store_fetch_version(struct arglist * desc);
char * store_fetch_summary(struct arglist * desc);
char * store_fetch_description(struct arglist * desc);
char * store_fetch_copyright(struct arglist * desc);
char * store_fetch_family(struct arglist * desc);
char * store_fetch_cve_id(struct arglist * desc);
char * store_fetch_bugtraq_id(struct arglist * desc);
char * store_fetch_xref(struct arglist * desc);
char * store_fetch_tag(struct arglist * desc);

#endif
