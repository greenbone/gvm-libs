#ifndef STORE_H
#define STORE_H


#define MAX_PREFS 32

#define MAGIC 0x45

struct pprefs {
	char type[9];
	char name[64];
	char dfl[320];
};
	
	
struct plugin {
	char magic;
 	int id;
 	char path	  	[256];
	int timeout;
	int category;
	char name	 	[128];	
	char version	  	[32];	
	char summary	 	[128];	
	char description 	[3192];	
	char copyright   	[128];	
	char family	 	[32];	
	
	char cve_id	 	[1404];
	char bid	 	[500];
	
	char xref	 	[1024];
	
	char dependencies	[512];
	char required_keys	[128];
	char excluded_keys	[128];
	char required_ports	[64];
	char required_udp_ports	[64];
	int has_prefs:1;
	};
	


int store_save_init();
int store_save_end();
int store_get_plugin(struct plugin *, char * );
struct arglist * store_save_plugin(struct arglist * plugin, char * path);
char * store_fetch_path(struct arglist * desc);
char * store_fetch_name(struct arglist * desc);
char * store_fetch_version(struct arglist * desc);
int store_fetch_timeout(struct arglist * desc);
char * store_fetch_summary(struct arglist * desc);
char * store_fetch_description(struct arglist * desc);
int store_fetch_category(struct arglist * desc);
char * store_fetch_copyright(struct arglist * desc);
char * store_fetch_family(struct arglist * desc);
char * store_fetch_cve_id(struct arglist * desc);
char * store_fetch_bugtraq_id(struct arglist * desc);
char * store_fetch_xref(struct arglist * desc);
struct arglist * store_fetch_dependencies(struct arglist * desc);
struct arglist * store_fetch_required_keys(struct arglist * desc);
struct arglist * store_fetch_excluded_keys(struct arglist * desc);
struct arglist * store_fetch_required_ports(struct arglist * desc);
struct arglist * store_fetch_required_udp_ports(struct arglist * desc);


#endif
