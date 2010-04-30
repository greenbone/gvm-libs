###############################################################################
# OpenVAS Vulnerability Test
# $Id$
#
# IPv6 Packet Forgery Test
#
# Authors:
# Preeti Subramanian <spreeti@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_id(1003157);
 script_version ("1.0-$Revision:$");

 script_name("Test IPv6 Packet Forgery");

 desc = "This plugin tests and demonstrates IPv6 packet forgery features.
It's purpose is to act as an example for development of IPv6 related
NASL scripts. It is not to be used for production.";

 script_description(desc);
 script_summary("IPv6 packet forgery Test");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 exit(0);
}


include("misc_func.inc");
include('global_settings.inc');

result = "";

IP6_v = 0x60;
IP6_P = 0x3a;#ICMPv6
IP6_HLIM = 0x40;

ip6_packet = forge_ipv6_packet(ip6_v: IP6_v,
                               ip6_p: IP6_P,
                               ip6_plen: 20,
                               ip6_hlim: IP6_HLIM,
                               ip6_src: this_host(),
                               ip6_dst: get_host_ip());

#--------------testing forge_icmp_v6_packet--------------------#
d = rand_str(length: 8);
icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:128, icmp_code:0, icmp_seq:0,
                            icmp_id: rand() % 65536, icmp_cksum:-1, data: d);

result = result + "ICMP: " + hexstr(icmp) + '\n';

filter = string("src " + get_host_ip() + "and dst " + this_host());
r = NULL;
r = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);

#########################################################################
#          TCP                                                          #
#########################################################################

IP6_v = 0x60;
IP6_P = 0x06;
IP6_HLIM = 0x40;

sport= (rand() % 64511) + 1024;
dport= 22;
ipid = 1234;
myack = 0x0000;
init_seq = rand();

#-------------testing forge_ipv6_packet--------------#
ip6_packet = forge_ipv6_packet(ip6_v: IP6_v,
                               ip6_p: IP6_P,
                               ip6_plen: 20,
                               ip6_hlim: IP6_HLIM,
                               ip6_src: this_host(),
                               ip6_dst: get_host_ip());
result = result + "IPv6 PACKET: " + hexstr(ip6_packet);

#-------------testing get_ipv6_element---------------#
element = string("ip6_src");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 src element: " + retval + '\n';

element = string("ip6_dst");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 dst element: " + retval + '\n';

element = string("ip6_v");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 version element: " + retval + '\n';

element = string("ip6_fl");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 flow element: " + retval + '\n';

element = string("ip6_hlim");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 hop limit element: " + retval + '\n';

element = string("ip6_nxt");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 next header element: " + retval + '\n';

element = string("ip6_plen");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 payload length element: " + retval + '\n';

element = string("ip6_tc");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 traffic class element: " + retval + '\n';

#-negative test-#
element = string("ip6_p");
retval = get_ipv6_element(ipv6:ip6_packet, element:element);
result = result + "return value get ip v6 next header element: " + retval + '\n';


#--------------testing set_ipv6_elements----------------------#
newval = set_ipv6_elements(ip6:ip6_packet);
result = result + "new IPv6 PACKET: " + hexstr(newval) + '\n';

#--------------testing forge_tcp_v6_packet--------------------#
tcp = forge_tcp_v6_packet(ip6:ip6_packet, th_sport:sport, th_dport:dport,
                          th_flags:TH_SYN, th_seq:init_seq,th_ack:0,
                          th_x2:0, th_off:5, th_win:512, th_urp:0);
result = result + "TCP: " + hexstr(tcp) + '\n';

#--------------testing get_tcp_v6_element--------------------#
element = string("th_sport");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 src port: " + retval + '\n';

element = string("th_dsport");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 dst port: " + retval + '\n';

element = string("th_seq");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 seq num: " + retval + '\n';

element = string("th_ack");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 ack: " + retval + '\n';

element = string("th_x2");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 x2: " + retval + '\n';

element = string("th_off");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 offset: " + retval + '\n';

element = string("th_flags");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 flags: " + retval + '\n';

element = string("th_win");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 win size: " + retval + '\n';

element = string("th_sum");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 sum: " + retval + '\n';

element = string("th_urp");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 urgent pointer: " + retval + '\n';

element = string("th_opt");
retval = get_tcp_v6_element(tcp:tcp, element:element);
result = result + "return value get tcp v6 urgent pointer: " + retval + '\n';

#------------------testing set_tcp_v6_elements---------------#
newval = set_tcp_v6_elements(tcp:tcp);
result = result + "new TCP v6 PACKET: " + hexstr(newval) + '\n';

#########################################################################
#          Send IPv6 packet                                             #
#########################################################################

#------------------testing send_v6packet---------------------#

filter = strcat('src port ', dport, ' and src host ', get_host_ip(),
                ' and dst port ', sport, ' and dst host ', this_host());

ret = send_v6packet(tcp, pcap_active : TRUE, pcap_timeout : 1, pcap_filter : filter);
result = result + "RET: " + hexstr(ret) + '\n';


#########################################################################
#          ICMP                                                         #
#########################################################################

IP6_v = 0x60;
IP6_P = 0x3a; #ICMPv6
IP6_HLIM = 0x40;

ip6_packet = forge_ipv6_packet(ip6_v: IP6_v,
                               ip6_p: IP6_P,
                               ip6_plen: 20,
                               ip6_hlim: IP6_HLIM,
                               ip6_src: this_host(),
                               ip6_dst: get_host_ip());

#--------------testing forge_icmp_v6_packet--------------------#
d = rand_str(length: 8);
icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:128, icmp_code:0, icmp_seq:0,
                            icmp_id: rand() % 65536, icmp_cksum:-1, data: d);
result = result + "ICMP: " + hexstr(icmp) + '\n';
filter = string("src " + get_host_ip() + "and dst " + this_host());
r = NULL;
r = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if(r)
  result = result + "return packet\n";

#--------------testing get_icmp_v6_element--------------------#
element = string("icmp_type");
retval = get_icmp_v6_element(icmp:icmp, element:element);
result = result + "return value get icmp type: " + retval + '\n';

element = string("icmp_code");
retval = get_icmp_v6_element(icmp:icmp, element:element);
result = result + "return value get icmp code: " + retval + '\n';

element = string("data");
retval = get_icmp_v6_element(icmp:icmp, element:element);
result = result + "return value get data: " + retval + '\n';

element = string("icmp_cksum");
retval = get_icmp_v6_element(icmp:icmp, element:element);
result = result + "return value get check sum: " + retval + '\n';

element = string("icmp_id");
retval = get_icmp_v6_element(icmp:icmp, element:element);
result = result + "return value get id: " + retval + '\n';

element = string("icmp_seq");
retval = get_icmp_v6_element(icmp:icmp, element:element);
result = result + "return value get sequence: " + retval + '\n';

#---------------test router solicit----------------#
#rs
d = raw_string(0x01, 0x01, 0x00, 0x1c, 0xc0, 0x87, 0xe9, 0x42);
icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:133, icmp_code:0, icmp_seq:0,
                            icmp_id: rand() % 65536, icmp_cksum:-1, data:d);
result = result + "ICMP: " + hexstr(icmp) + '\n';
filter = string("src " + get_host_ip() + "and dst " + this_host());
r = NULL;
r = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if(r)
  result = result + "return packet\n";

#---------------test router advert-----------------#
#ra
d = raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x03, 0x04, 0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00,
               0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x00,
               0x2a, 0x01, 0x01, 0x30, 0x00, 0x12, 0x56, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:134, icmp_code:0, icmp_seq:0,
                            icmp_id: rand() % 65536, icmp_cksum:-1, data:d);
result = result + "ICMP: " + hexstr(icmp) + '\n';
filter = string("src " + get_host_ip() + "and dst " + this_host());
r = NULL;
r = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if(r)
  result = result + "return packet\n";

#---------------test neighbor solicit-----------------#
#ns
d = raw_string(0x02, 0x01, 0x00, 0x1f, 0xd0, 0xbb, 0x5c, 0xd5);
icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:135, icmp_code:0, icmp_seq:0,
        icmp_id: rand() % 65536, icmp_cksum:-1, data:d);
result = result + "ICMP: " + hexstr(icmp) + '\n';
filter = string("src " + get_host_ip() + "and dst " + this_host());
r = NULL;
r = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if(r)
  result = result + "return packet\n";

#---------------test neighbor advert-----------------#
#na - data is null
icmp = forge_icmp_v6_packet(ip6: ip6_packet, icmp_type:136, icmp_code:0,
                            icmp_cksum:-1, flags:0x00000020); #unsolicited advertisement
result = result + "ICMP: " + hexstr(icmp) + '\n';
filter = string("src " + get_host_ip() + "and dst " + this_host());
r = NULL;
r = send_v6packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if(r)
  result = result + "return packet\n";


#########################################################################
#          UDP                                                          #
#########################################################################

myaddr = this_host();
dstaddr = get_host_ip();
returnport = rand() % 65535;

mystring = string("OPTIONS sip:", get_host_name(), " SIP/2.0\r\nVia: SIP/2.0/UDP ",
                  myaddr, ":", returnport, "\r\nFrom: Test <sip:", myaddr, ":",
                  returnport, ">\r\nTo: <sip:", myaddr, ":", returnport,
                  ">\r\nCall-ID: 12312312@", myaddr,
                  "\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n");

len = strlen(mystring);

ippkt = forge_ip_packet(ip_hl   :5,
                        ip_v    :4,
                        ip_tos  :0,
                        ip_len  :20,
                        ip_id   :31337,
                        ip_off  :0,
                        ip_ttl  :64,
                        ip_p    :IPPROTO_UDP,
                        ip_src  :myaddr);

#-------------testing udp v6 packet--------------#
IP6_v = 0x60;
IP6_P = IPPROTO_UDP;
IP6_HLIM = 0x40;
ip6_packet = forge_ipv6_packet(ip6_v: IP6_v,
                               ip6_p: IP6_P,
                               ip6_plen: 20,
                               ip6_hlim: IP6_HLIM,
                               ip6_src: this_host(),
                               ip6_dst: get_host_ip());

udppacket = forge_udp_v6_packet(ip6: ip6_packet,
                                uh_sport: returnport,
                                uh_dport: 56618,
                                uh_ulen: 8 + len,
                                data: mystring);

result = result + "udp packet: " + hexstr(udppacket) + '\n';

filter = string("udp and src " + this_host() + " and dst port ", returnport);
rpkt = send_v6packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
if(rpkt)
  result = result + "return packet";

#-------------testing get udp v6 packet--------------#
data = get_udp_v6_element(udp:udppacket, element:"data");
result = result + "data: " + data + '\n';
sport = get_udp_v6_element(udp:udppacket, element:"uh_sport");
result = result + "source port: " + sport + '\n';
dport = get_udp_v6_element(udp:udppacket, element:"uh_dport");
result = result + "dest port: " + dport + '\n';
len = get_udp_v6_element(udp:udppacket, element:"uh_ulen");
result = result + "length: " + len + '\n';
sum = get_udp_v6_element(udp:udppacket, element:"uh_sum");
result = result + "sum: " + sum + '\n';

#-------------testing set udp v6 packet--------------#
mystring = string("OPTIONS OPTIONS");
len = strlen(mystring);
new_udppacket = set_udp_v6_elements(udp: udppacket,
                                    uh_sport: returnport,
                                    uh_dport: 631,
                                    uh_ulen: 8 + len,
                                    data: mystring);
result = result + "new udp packet: " + hexstr(new_udppacket) + '\n';
new_rpkt = send_v6packet(new_udppacket, pcap_active:TRUE, pcap_filter:filter,
                         pcap_timeout:1);
if(rpkt)
  result = result + "return packet";

#-------------testing dump udp v6 packet--------------#
result = result + "dump udp v6 packet\n";
dump_udp_v6_packet(udppacket);


#########################################################################
#          tcp ping, send capture                                       #
#########################################################################
port = 22;

buffer = raw_string(0x00, 0x00) +

crap(length:1500, data:'A');
# Random data
soc = open_sock_tcp(port);
if (soc)
{
  result = result + "src host: " + get_host_ip() + " dst host: " + this_host() + '\n';
  filter = strcat('src host ', get_host_ip(), ' and dst host ', this_host());
#-----------------test send_capture-------------------  #
  r = send_capture(pcap_filter:filter, timeout:10, socket:soc, data:'A', length:1500, option:1);
  if(r)  {result = result + "RECVED" + hexstr(r) + "port: " + port + '\n';}
#-----------------test tcp ping ---------------------   #
  r = tcp_ping();
  result = result + "result: " + r + '\n';
}

security_note(data: result);
