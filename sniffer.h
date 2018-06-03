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

#include "filter.h"

#define MAX_BYTE_CAPTURE 65535

#define SUCCESS 0
#define FAILURE 1

#define TCP 2
#define UDP 3

#define NOT_PROMISE 0
#define PROMISE 1

#define WAIT_MILSEC 512

#define INFINITY -1

#define IP_ADDRESS_SIZE 16

#define EXPRESSION_SIZE 200

#define SIZE_ETHERNET 14
#define SIZE_IP 20

#define IP_HL(num) (num & 0x0f)

#define QUERY_LEN 100

#define SRC 0
#define DST 1

#define MAC_SIZE 20
int captrue_traffic();

void print_info(char*, bpf_u_int32*, bpf_u_int32*, char);

char *get_IP_address();