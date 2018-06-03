#include "filter.h"

int print_match(const struct ipt_entry_match *entry_match, 
        int dir, ushort *rule_port_begin,
        ushort *rule_port_end){

  struct ipt_tcp *tcp_info;
  struct ipt_udp *udp_info;
  const char* name = entry_match->u.user.name;

  //printf("Now name: %s\n", name);

  if(name && (strncmp(name, "tcp", strlen(name)) == 0)){
    tcp_info = (struct ipt_tcp*)entry_match->data;

    if(dir == SRC){
      *rule_port_begin = tcp_info->dpts[0];
      *rule_port_end = tcp_info->dpts[1];
    }else if(dir == DST){
      *rule_port_begin = tcp_info->spts[0];
      *rule_port_end = tcp_info->spts[1];
    }

    return SUCCESS;
  }else if(name && (strncmp(name, "udp", strlen(name)) == 0)){
    udp_info = (struct ipt_udp*)entry_match->data;

    if(dir == SRC){
      *rule_port_begin = udp_info->dpts[0];
      *rule_port_end = udp_info->dpts[1];
    }else if(dir == DST){
      *rule_port_begin = udp_info->spts[0];
      *rule_port_end = udp_info->spts[1];
    }

    return SUCCESS;
  }else{
    return FAILURE;
  }
}

int is_rule_same(in_addr_t capture_saddr, in_addr_t capture_daddr,
  int capture_protocol, u_short capture_sport, 
  u_short capture_dport, int dir, in_addr_t rule_shost,
  in_addr_t rule_dhost, int rule_protocol, 
  u_short rule_port_begin, u_short rule_port_end){

  if(capture_saddr != rule_shost)
    return FAILURE;
  if(capture_daddr != rule_dhost)
    return FAILURE;
  if(capture_protocol != rule_protocol)
    return FAILURE;
  if(dir == SRC){
    if(capture_dport < rule_port_begin 
      || capture_dport > rule_port_end)

      return FAILURE;
  }else if(dir == DST){
        if(capture_sport < rule_port_begin 
      || capture_sport > rule_port_end)

      return FAILURE;
  }

  return SUCCESS;
}

int is_rule_exist(u_char *eth_mac_shost, 
  u_char *eth_mac_dhost, 
  struct in_addr ip_shost, struct in_addr ip_dhost, 
  int ip_protocol, u_short general_sport, 
  u_short general_dport, int dir){

  struct xtc_handle *h;
  const struct ipt_entry *entry;
  const char *target_name; 
  struct ipt_entry_target *t;

  //u_char rule_mac_shost[MAC_SIZE]; 
  //u_char rule_mac_dhost[MAC_SIZE];
  in_addr_t rule_shost; 
  in_addr_t rule_dhost; 
  int rule_protocol;

  /* check the range instead of certain port number */
  ushort rule_port_begin;
  ushort rule_port_end; 

  int match_status;

  match_status = 0;

  if((h = iptc_init("filter")) == NULL){
    perror("iptc_init");
    goto error;
  }

  if(dir == DST)
    entry = iptc_first_rule("INPUT", h);
  else if(dir == SRC)
    entry = iptc_first_rule("OUTPUT", h);

  if(entry == NULL)
    goto error;

  for(; entry; entry = iptc_next_rule(entry, h)){

    rule_shost = entry->ip.src.s_addr;  
    rule_dhost = entry->ip.dst.s_addr;  
    rule_protocol = entry->ip.proto;

    if (entry->target_offset) {   
      match_status = IPT_MATCH_ITERATE(entry, print_match, 
        dir, &rule_port_begin, &rule_port_end);                                 
    }

    if(is_rule_same(ip_shost.s_addr, ip_dhost.s_addr, 
      ip_protocol, general_sport, general_dport, dir, 
      rule_shost, rule_dhost, rule_protocol,
      rule_port_begin, rule_port_end) == SUCCESS){

      iptc_free(h);
      return SUCCESS;
    }
  }

  goto error;

error:
  iptc_free(h);
  return FAILURE;
}

int insert_rule(u_char *eth_mac_shost, 
  u_char *eth_mac_dhost, 
  struct in_addr ip_shost, struct in_addr ip_dhost, 
  int ip_protocol, u_short general_sport, 
  u_short general_dport, char *verdict, int dir){

  struct xtc_handle *h;

  struct ipt_entry_target *entry_target;

  struct ipt_entry *entry;

  struct ipt_entry_match *match_pro;
  struct ipt_tcp *tcp_info;
  struct ipt_udp *udp_info;

  struct ipt_entry_match *match_limit;
  struct xt_rateinfo *rate_info;

  struct ipt_entry_match *match_mac;
  struct xt_mac_info *mac_info;

  size_t match_size;
  size_t target_size;
  size_t entry_size;
  size_t protocol_size;

  char* IN_or_OUT;

  IN_or_OUT = (char *)malloc(sizeof(char) * QUERY_LEN);
  if(IN_or_OUT == NULL){
    perror("IN_or_OUT malloc");
    return FAILURE;    
  }
  memset(IN_or_OUT, 0, strlen(IN_or_OUT));
  
  if(dir == DST)
    (void)strncpy(IN_or_OUT, "INPUT", strlen("INPUT"));
  else if(dir == SRC)
    (void)strncpy(IN_or_OUT, "OUTPUT", strlen("OUTPUT"));

  if(ip_protocol == IPPROTO_TCP)
    protocol_size = XT_ALIGN(sizeof(struct ipt_tcp));
  else if(ip_protocol == IPPROTO_UDP)
    protocol_size = XT_ALIGN(sizeof(struct ipt_udp));

  if(dir == DST){
    match_size = XT_ALIGN(sizeof(struct ipt_entry_match)) * 3 
    + protocol_size + XT_ALIGN(sizeof(struct xt_rateinfo))
    + XT_ALIGN(sizeof(struct xt_mac_info));
  }else if(dir == SRC){
    match_size = XT_ALIGN(sizeof(struct ipt_entry_match)) * 2
    + protocol_size + XT_ALIGN(sizeof(struct xt_rateinfo));
  }

  target_size = XT_ALIGN(sizeof(struct ipt_entry_target)) 
    + XT_ALIGN(sizeof(int));
  entry_size = sizeof(*entry) + target_size + match_size;

  entry = malloc(entry_size);
  if(entry == NULL){
    perror("entry malloc");
    goto error;
  }
  memset(entry, 0, entry_size);

/////////////////Entry////////////////////////////////////

  char shost[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_shost, shost, INET_ADDRSTRLEN);
  entry->ip.src.s_addr = inet_addr(shost);
  entry->ip.smsk.s_addr= inet_addr("255.255.255.255");

  char dhost[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_dhost, dhost, INET_ADDRSTRLEN);
  entry->ip.dst.s_addr = inet_addr(dhost);
  entry->ip.dmsk.s_addr= inet_addr("255.255.255.255");
  
  strcpy(entry->ip.iniface, "eth0");

  for(int i = 0; i < (strlen("eth0") + 1); i++)
    entry->ip.iniface_mask[i] = 0xff;

  for(int i = 0; i < (strlen("eth0") + 1); i++)
    entry->ip.outiface_mask[i] = 0xff;

  entry->ip.proto = ip_protocol;
  entry->target_offset = sizeof(*entry) + match_size;
  entry->next_offset = entry_size;

///////////////////Entry_Match//////////////////////////////

  match_pro = (struct ipt_entry_match *)entry->elems;
  match_pro->u.user.match_size = 
    XT_ALIGN(sizeof(struct ipt_entry_match))
    + protocol_size;

  if(ip_protocol == IPPROTO_TCP)
    (void)strncpy(match_pro->u.user.name, "tcp", strlen("tcp"));
  else if(ip_protocol == IPPROTO_UDP)
    (void)strncpy(match_pro->u.user.name, "udp", strlen("udp"));

///////////////////Protocol_Info////////////////////////////

  if(ip_protocol == IPPROTO_TCP){
    tcp_info = (struct ipt_tcp*)match_pro->data;

    if(dir == DST){
      tcp_info->spts[0] = general_sport;
      tcp_info->spts[1] = general_sport;
      tcp_info->dpts[0] = 0;
      tcp_info->dpts[1] = 65535;
    }else if(dir == SRC){
      tcp_info->spts[0] = 0;
      tcp_info->spts[1] = 65535;
      tcp_info->dpts[0] = general_dport;
      tcp_info->dpts[1] = general_dport;
    }
  }else if(ip_protocol == IPPROTO_UDP){
    udp_info = (struct ipt_udp*)match_pro->data;

    if(dir == DST){
      udp_info->spts[0] = general_sport;
      udp_info->spts[1] = general_sport;
      udp_info->dpts[0] = 0;
      udp_info->dpts[1] = 65535;
    }else if(dir == SRC){
      udp_info->spts[0] = 0;
      udp_info->spts[1] = 65535;
      udp_info->dpts[0] = general_dport;
      udp_info->dpts[1] = general_dport;
    }
  }

///////////////////Entry_Match//////////////////////////////

  match_limit = (struct ipt_entry_match *)(entry->elems
                + match_pro->u.user.match_size); 
  match_limit->u.user.match_size = 
      XT_ALIGN(sizeof(struct ipt_entry_match))
    + XT_ALIGN(sizeof(struct xt_rateinfo));

  (void)strncpy(match_limit->u.user.name, "limit",
                 strlen("limit"));

///////////////////Limit_Info//////////////////////////////
  /* In case of DDos Attack */
  rate_info = (struct xt_rateinfo *)match_limit->data;
  rate_info->avg = 5;
  rate_info->burst = 10;

///////////////////Entry_info/////////////////////////////////

  if(dir == DST){
    match_mac = (struct ipt_entry_match *)(entry->elems 
      + match_pro->u.user.match_size 
      + match_limit->u.user.match_size); 
    
    match_mac->u.user.match_size = 
      XT_ALIGN(sizeof(struct ipt_entry_match))
      + XT_ALIGN(sizeof(struct xt_mac_info));

    (void)strncpy(match_mac->u.user.name, 
      "mac", strlen("mac"));

/////////////////MAC_info///////////////////////////////

  mac_info = (struct xt_mac_info *)match_mac->data;
  (void)strncpy((char *)mac_info->srcaddr, (char *)eth_mac_shost,
                  strlen((char *)eth_mac_shost));
  }

///////////////////Entry_Target//////////////////////////////

  entry_target = (struct ipt_entry_target *)(entry->elems
                  + match_size);
  entry_target->u.user.target_size = target_size;
  strcpy(entry_target->u.user.name, verdict);

///////////////////Submit Rule////////////////////////////

  if((h = iptc_init("filter")) == NULL){
    perror("iptc_init");
    goto error;
  }

  if(iptc_append_entry(IN_or_OUT, entry, h) == 0){
    perror("iptc_append_entry");
    goto error;
  }

  if(iptc_commit(h) == 0){
    perror("iptc_commit");
    goto error;
  }

  free(entry);
  iptc_free(h);

  free(IN_or_OUT);
  return SUCCESS;

error:
  free(entry);
  iptc_free(h);

  free(IN_or_OUT);
  return FAILURE;
}