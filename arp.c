/* arp/arp.c */

#include "arp.h"



/* Sends an ARP request
    
   sockfd is the file descriptor of the socket to use to send the
   frame, should be a raw socket (AF_PACKET), which accepts ARP
   (ETH_P_ALL or ETH_P_ARP)
   ifindex is the index of the network interface
   ipaddr is the source IP address
   macaddr is the source MAC address
   target_ip is the IP address to be queried via ARP

   The function returns 0 upon success, EXIT_FAILURE otherwise.
*/
int send_arp_request(int sockfd, int ifindex, struct sockaddr_in *ipaddr, unsigned char *macaddr, struct in_addr target_ip)
{

  /* DEFINITION OF THE DESTINATION */
  
  /* The destination of the packet is contained in a struct
     sockaddr_ll, that we fill with the broadcast address
     ff:ff:ff:ff:ff:ff */
  /* Broadcast address: */
  const unsigned char ether_broadcast_addr[]= {0xff,0xff,0xff,0xff,0xff,0xff};

  struct sockaddr_ll addr;
  addr.sll_family = AF_PACKET; /* always AF_PACKET */
  addr.sll_protocol = htons(ETH_P_ARP); /* physical-layer protocol */
  addr.sll_ifindex = ifindex; /* interface number */
  addr.sll_halen = ETHER_ADDR_LEN; /* length of address */
  /* physical-layer address: */
  memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

#ifdef DEBUG
  printf("[OK] Destination structure (struct sockaddr_ll) "
	 "constructed successfully\n");
#endif

  
  /* ====================================================================== */

  /* CONSTRUCTION OF THE FRAME */

  /* We can now build the ARP request frame, using the structures
     defined in <netinet/if_ether.h> (included by
     <netinet/ether.h>). */
  struct ether_arp request;
  request.arp_hrd = htons(ARPHRD_ETHER); /* hardware type: Ethernet */
  request.arp_pro = htons(ETH_P_IP); /* Protocol type: IP */
  request.arp_hln = ETHER_ADDR_LEN; /* Hardware address length */
  request.arp_pln = sizeof(in_addr_t); /* Protocol address length */
  request.arp_op = htons(ARPOP_REQUEST); /* Operation code */
  /* Target hardware address: 0 since this is one we want */
  memset(&request.arp_tha, 0, sizeof(request.arp_tha));
  /* Target protocol address: we put the IP address for which we want
     the layer-2 address */
  memcpy(&request.arp_tpa, &target_ip.s_addr, sizeof(request.arp_tpa));
  /* Source hardware address */
  memcpy(&request.arp_sha, macaddr, sizeof(request.arp_sha));
  /* Source protocol (IP) address */
  memcpy(&request.arp_spa, &ipaddr->sin_addr, sizeof(request.arp_spa));

#ifdef DEBUG
  printf("[OK] ARP request structure (struct ether_arp) "
	 "constructed successfully\n");
#endif


  /* ====================================================================== */

  /* SEND THE FRAME */

  int err = sendto(sockfd, &request, sizeof(request), 0,
		   (struct sockaddr *) &addr, sizeof(addr));
  if (err == -1) {
    perror("[FAIL] sendto()");
    exit(EXIT_FAILURE);
  }
#ifdef DEBUG
  printf("[OK] Frame sent\n");
#endif
  


  return 0;
}

