#ifndef PLUGUTILS_H
#define PLUGUTILS_H

char * _plug_get_version(struct arglist *);
int    _plug_get_id(struct arglist*);
char * _plug_get_cve_id(struct arglist*);
char * _plug_get_bugtraq_id(struct arglist*);
char * _plug_get_xref(struct arglist *);
char * _plug_get_family(struct arglist*);
struct arglist * _plug_get_required_keys(struct arglist*);
struct arglist * _plug_get_excluded_keys(struct arglist*);
struct arglist * _plug_get_required_ports(struct arglist*);
struct arglist * _plug_get_required_udp_ports(struct arglist*);
struct arglist * _plug_get_deps(struct arglist*);
int _plug_get_timeout(struct arglist*);
char * _plug_get_name(struct arglist*);
char * _plug_get_summary(struct arglist*);
char * _plug_get_description(struct arglist*);
char * _plug_get_copyright(struct arglist*);
char * _plug_get_fname(struct arglist *);
int  _plug_get_category(struct arglist*);
void _add_plugin_preference(struct arglist*, const char*, const char*, const char*, const char*);



#endif
