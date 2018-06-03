#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <time.h>
#include <ifaddrs.h>

#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libiptc/libiptc.h>
#include "linux/netfilter/xt_limit.h"
#include "linux/netfilter/xt_physdev.h"
#include "linux/netfilter/xt_mac.h"

int insert_rule(u_char *, 
	u_char *, 
	struct in_addr, struct in_addr, 
	int, u_short, 
	u_short, char *, int);

int is_rule_exist(u_char *, 
	u_char *, 
	struct in_addr, struct in_addr, 
	int, u_short, 
	u_short, int);

#define FAILURE 1
#define SUCCESS 0

#define SRC 0
#define DST 1

#define QUERY_LEN 100

#define MAC_SIZE 20