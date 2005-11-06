#ifndef HG_ADD_HOSTS_H__
#define HG_ADD_HOSTS_H__

int hg_add_host(struct hg_globals *, char *);
int hg_add_comma_delimited_hosts(struct hg_globals *, int);
void hg_add_host_with_options(struct hg_globals *, char *, struct in_addr,
			       int, int,int, struct in_addr *);
void hg_add_domain(struct hg_globals *, char *);	       
void hg_add_subnet(struct hg_globals *, struct in_addr, int);			     
#endif
