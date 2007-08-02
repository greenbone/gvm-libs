#ifndef HL2_UTILS_H__
#define HL2_UTILS_H__

struct in_addr hg_resolv(char *);
int hg_get_name_from_ip(struct in_addr, char *, int);
char * hg_name_to_domain(char * name);
void hg_hosts_cleanup(struct hg_host *);
void hg_host_cleanup(struct hg_host *);
#endif
