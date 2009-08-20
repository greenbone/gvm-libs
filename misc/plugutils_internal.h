#ifndef PLUGUTILS_INTERNAL_H
#define PLUGUTILS_INTERNAL_H

char * _plug_get_version(struct arglist *);
char * _plug_get_cve_id(struct arglist*);
char * _plug_get_bugtraq_id(struct arglist*);
char * _plug_get_xref(struct arglist *);
char * _plug_get_tag(struct arglist *);
char * _plug_get_family(struct arglist*);
char * _plug_get_summary(struct arglist*);
char * _plug_get_description(struct arglist*);
char * _plug_get_copyright(struct arglist*);
void _add_plugin_preference(struct arglist*, const char*, const char*, const char*, const char*);

#endif
