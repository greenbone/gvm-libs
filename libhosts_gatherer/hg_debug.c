#include <includes.h>
#include "hosts_gatherer.h"

void
hg_dump_hosts(hosts)
 struct hg_host * hosts;
{
 while(hosts && hosts->next)
 {
  printf("\t[ %s ]\tT: %d\tA : %d\tN : %d\t(%s)\n", inet_ntoa(hosts->addr),
  					hosts->tested, hosts->alive,
					hosts->cidr_netmask,
					hosts->hostname);
  hosts = hosts->next;
 }
}
