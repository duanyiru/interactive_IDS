#include "sniffer.h"

int get_mac_info(const u_char* packet, 
	u_char *eth_mac_shost,
	u_char *eth_mac_dhost){
	
	struct ether_header *eptr;
	uint16_t eth_type;

	eptr = (struct ether_header *)packet;
	eth_type = ntohs(eptr->ether_type);

	if(strncpy((char *)eth_mac_shost, (char *)eptr->ether_shost, 
		strlen((char *)eptr->ether_shost)) == NULL){

		perror("In capture packet, malloc");
		return FAILURE;
	}

	if(strncpy((char *)eth_mac_dhost, (char *)eptr->ether_dhost, 
		strlen((char *)eptr->ether_dhost)) == NULL){

		perror("In capture packet, malloc");
		return FAILURE;
	}

	printf("MAC Address: ");
	int i = ETHER_ADDR_LEN;
	do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":", 
        	*eth_mac_shost++);
    }while(--i>0);

    printf(" ->");

    i = ETHER_ADDR_LEN;
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",
        	*eth_mac_dhost++);
    }while(--i>0);
    printf("\n");
    
	/*
	process IP packet, if not, skip it. Since 
	the requirement need us to manipulate the IP address and
	MAC address.
	*/
	if(eth_type != ETHERTYPE_IP){
		fprintf(stderr, "Not IP header, skip it\n\n");
		return FAILURE;
	}

	return SUCCESS;
}

int get_ip_info(const u_char* packet, struct in_addr* ip_shost,
	struct in_addr* ip_dhost, u_short* general_sport, 
	u_short* general_dport, int *dir){

	struct ip *ip_header;
	u_char ip_protocol;

	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	char *local_address;

	ip_header = (struct ip*)(packet + SIZE_ETHERNET);
	ip_protocol = ip_header->ip_p;
	
	*ip_shost = ip_header->ip_src;
	*ip_dhost = ip_header->ip_dst;

	char saddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip_shost, saddr, INET_ADDRSTRLEN);

	char daddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip_dhost, daddr, INET_ADDRSTRLEN);

	printf("IP Address: %s -> %s\n", saddr, daddr);

	local_address = get_IP_address();
	if(local_address && 
		(strncmp(local_address, saddr, strlen(saddr)) == 0))
		*dir = SRC;
	else if(local_address && 
		(strncmp(local_address, daddr, strlen(daddr)) == 0))
		*dir = DST;
	else 
		return FAILURE;

	u_int ip_size = ip_header->ip_hl * 4;
	if(ip_size < SIZE_IP){
		fprintf(stderr, "invalid IP header length:%u\n",
			ip_size );
		return FAILURE;
	}

	if(ip_protocol == IPPROTO_TCP){
		tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET 
			+ ip_size);
		*general_sport = tcp_header->th_sport;
		*general_dport = tcp_header->th_dport;

		printf("Protocol: TCP\n");
		printf("Port src: %u dst: %u\n", *general_sport, 
			*general_dport);

		return IPPROTO_TCP;
	}else if(ip_protocol == IPPROTO_UDP){
		udp_header = (struct udphdr*)(packet + SIZE_ETHERNET 
			+ ip_size);
		*general_sport = udp_header->uh_sport;
		*general_dport = udp_header->uh_dport;

		printf("Protocol: UDP\n");
		printf("Port src: %u dst: %u\n", *general_sport, 
			*general_dport);

		return IPPROTO_UDP;
	}else{
		printf("Neither TCP or UDP, skip it\n\n");

		return FAILURE;
	}
}

void process_packet(u_char *useless, 
	const struct pcap_pkthdr* pkthdr, const u_char* packet){

	/*
	In here, the u_char* packet points 
	to the first byte of entire packet, cool!
	*/
	u_char eth_mac_shost[MAC_SIZE];
	u_char eth_mac_dhost[MAC_SIZE];

	struct in_addr ip_shost;
	struct in_addr ip_dhost;

	u_short general_sport;
	u_short general_dport;

	int ip_protocol;

	/* identify local address is src or dest address*/
	int dir;	

	int client_len;
	char client_answer[QUERY_LEN];

	/* No ICMP since it has no port variable provide */

	/*
	process IP packet, if not, skip it. Since 
	the requirement need us to manipulate the IP address and
	MAC address.
	*/

	/* Take Ethernet part first */
	if(get_mac_info(packet, eth_mac_shost, 
		eth_mac_dhost) == FAILURE)
		return;

	/* Take IP header Second */
	memset(&ip_shost, 0, sizeof(struct in_addr));
	memset(&ip_dhost, 0, sizeof(struct in_addr));
	general_sport = 0;
	general_dport = 0;

	ip_protocol = get_ip_info(packet, &ip_shost, &ip_dhost, 
		&general_sport, &general_dport, &dir);
	if(ip_protocol == FAILURE)
		return;

	/* 
		Check the rule is exist or not, and do not pop up
		same source and destination pairs.
	*/
	if(is_rule_exist(eth_mac_shost, eth_mac_dhost, ip_shost,
			ip_dhost, ip_protocol, general_sport, 
			general_dport, dir) == SUCCESS){

		printf("This packet already processed, skip it\n\n");
		return;
	}

	/*Ask from client*/
	printf("\nHow to deal with this pair? [A]ccept\t[D]eny\t[I]gnore\n");

	scanf("%s", client_answer);
	client_len = strlen(client_answer);

	if((client_len == 1) && (client_answer[0] == 'A')){
		insert_rule(eth_mac_shost, eth_mac_dhost, ip_shost,
			ip_dhost, ip_protocol, general_sport, 
			general_dport, "ACCEPT", dir);
	}else if((client_len == 1) && (client_answer[0] == 'D')){
		insert_rule(eth_mac_shost, eth_mac_dhost, ip_shost,
			ip_dhost, ip_protocol, general_sport, 
			general_dport, "DROP", dir);
	}else if((client_len == 1) && (client_answer[0] == 'I')){
		return;
	}else{
		printf("Invalid input, ingore this part by default\n");
		return;
	}
}

char *connect_IP(char *address){
	char *res;
	char one[] = "src ";
	char two[] = " or dst ";

	if((res = (char *)malloc(sizeof(char) * EXPRESSION_SIZE)) 
		== NULL){
		perror("malloc ");
		return NULL;
	}
	memset(res, 0, sizeof(char) * EXPRESSION_SIZE);

	if((strncat(res, one, strlen(one))) == NULL){
		perror("strncat");
		return NULL;	
	}

	if(strncat(res, address, strlen(address)) == NULL){
		perror("strncat");
		return NULL;	
	}

	if((strncat(res, two, strlen(two))) == NULL){
		perror("strncat");
		return NULL;	
	}

	if((strncat(res, address, strlen(address))) == NULL){
		perror("strncat");
		return NULL;	
	}

	return res;
}

char *get_IP_address(){
	struct ifaddrs *ifaddr;
	char *address;

	if((address = (char *)malloc(sizeof(char) * IP_ADDRESS_SIZE))
		== NULL){
		perror("malloc ");
		return NULL;
	}

	if(getifaddrs(&ifaddr) == -1){
		perror("getifaddrs ");
		return NULL;
	}

	for(struct ifaddrs *ifa = ifaddr; ifa != NULL; 
		ifa = ifa->ifa_next){

		if(ifa->ifa_addr && 
			ifa->ifa_addr->sa_family == AF_INET){

			struct sockaddr_in *p_addr = 
				(struct sockaddr_in*)ifa->ifa_addr;

			address = inet_ntoa(p_addr->sin_addr);
		}
	}

	return address;
}

void print_dev_info(char *device, bpf_u_int32 *netp, 
	bpf_u_int32 *maskp, char errbuf[]){
	
	struct in_addr addr;
	char *net;
	char *mask;

	device = pcap_lookupdev(errbuf);
	if(device == NULL){
		perror("pcap_lookupdev ");
		return;
	} 

	if(pcap_lookupnet(device, netp, maskp, errbuf) == -1){
		perror("pcap_lookupnet ");
		return;
	}
	printf("Device: %s\n", device);

	/*network address*/
	addr.s_addr = *netp;

	net = inet_ntoa(addr);
	if(net == NULL){
		perror("inet_ntoa ");
		return;
	}
	printf("Net: %s\n", net);

	addr.s_addr = *maskp;

	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa ");
		return;
	}
	printf("Mask: %s\n\n", mask);
}

int captrue_traffic(){
	pcap_t *descr;						/* capture handle*/
	int count;	
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;						
	char *ip_address;
	bpf_u_int32 netp;					/* device IP address */
	bpf_u_int32 maskp;					/* device mask */
	struct bpf_program packet_filter;	/* compiled filter */
	
	char *filter_exp;

	count = 0;
	device = NULL;
	descr = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	netp = 0;
	maskp = 0;

	/*print info*/
	printf("Source Info:\n");
	print_dev_info(device, &netp, &maskp, errbuf);
	device = pcap_lookupdev(errbuf);

	descr = pcap_open_live(device, BUFSIZ, PROMISE, 
		WAIT_MILSEC, errbuf);
	if(descr == NULL){

		perror("pcap_open_live ");
		return FAILURE;
	}

	/*
	Only support Ethernet so far, we can provide more
	than that depend on the demand
	*/
	if(pcap_datalink(descr) != DLT_EN10MB){
		fprintf(stderr, "Device:%s does not support Ethernet\n", device);
	}

	/*get host IP address*/
	ip_address = get_IP_address();
	filter_exp = connect_IP(ip_address);

	if(pcap_compile(descr, &packet_filter, filter_exp, 0,
	 PCAP_NETMASK_UNKNOWN) == -1){
		perror("pcap_compile");
		return FAILURE;
	}

	if(pcap_setfilter(descr, &packet_filter) == -1){
		perror("pcap_setfilter");
		return FAILURE;
	}

	/*which mean loop forever*/
	pcap_loop(descr, INFINITY, process_packet, 
		(u_char *)&count);

	pcap_freecode(&packet_filter);
	pcap_close(descr);

	return SUCCESS;
}