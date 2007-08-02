#ifndef HG_FILTER_H__
#define HG_FILTER_H__

int  hg_filter_host(struct hg_globals *, char *, struct in_addr);
int  hg_filter_subnet(struct hg_globals *, struct in_addr, int);
int  hg_filter_domain(struct hg_globals *, char *);
#endif
