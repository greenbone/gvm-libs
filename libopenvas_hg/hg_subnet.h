#ifndef HG_SUBNET_H__
#define HG_SUBNET_H__
void hg_gather_subnet_hosts(struct hg_globals *, struct hg_host * );
struct in_addr cidr_get_first_ip(struct in_addr, int);
struct in_addr cidr_get_last_ip (struct in_addr, int);
#endif
