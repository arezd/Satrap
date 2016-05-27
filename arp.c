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



/* Sends an ARP reply

   sockfd: file descriptor of the socket
   ifindex: index of the network interface
   sender_ip: source IP address
   sender_mac: source MAC address
   target_ip: IP address to which the answer is destined
   target_mac: MAC address of the target

   The function returns 0 on success, or exits with EXIT_FAILURE.
 */
int send_arp_reply(int sockfd, int ifindex, struct sockaddr_in *sender_ip, unsigned char *sender_mac, struct in_addr target_ip, unsigned char *target_mac)
{

  /* DEFINITION OF THE DESTINATION */
  
  /* The destination of the packet is contained in a struct
     sockaddr_ll */
  struct sockaddr_ll addr;
  addr.sll_family = AF_PACKET; /* always AF_PACKET */
  addr.sll_protocol = htons(ETH_P_ARP); /* physical-layer protocol */
  addr.sll_ifindex = ifindex; /* interface number */
  addr.sll_halen = ETHER_ADDR_LEN; /* length of address */
  /* physical-layer address: */
  memcpy(addr.sll_addr, target_mac, ETHER_ADDR_LEN);

#ifdef DEBUG
  printf("[OK] Destination structure (struct sockaddr_ll) "
	 "constructed successfully\n");
#endif

  
  /* ====================================================================== */

  /* CONSTRUCTION OF THE FRAME */

  /* We can now build the ARP reply frame, using the structures
     defined in <netinet/if_ether.h> (included by
     <netinet/ether.h>). */
  struct ether_arp reply;
  reply.arp_hrd = htons(ARPHRD_ETHER); /* hardware type: Ethernet */
  reply.arp_pro = htons(ETH_P_IP); /* Protocol type: IP */
  reply.arp_hln = ETHER_ADDR_LEN; /* Hardware address length */
  reply.arp_pln = sizeof(in_addr_t); /* Protocol address length */
  reply.arp_op = htons(ARPOP_REPLY); /* Operation code */
  /* Target hardware address: 0 since this is one we want */
  memcpy(&reply.arp_tha, target_mac, sizeof(reply.arp_tha));
  /* Target protocol address: we put the IP address for which we want
     the layer-2 address */
  memcpy(&reply.arp_tpa, &target_ip.s_addr, sizeof(reply.arp_tpa));
  /* Sender hardware address */
  memcpy(&reply.arp_sha, sender_mac, sizeof(reply.arp_sha));
  /* Sender protocol (IP) address */
  memcpy(&reply.arp_spa, &sender_ip->sin_addr, sizeof(reply.arp_spa));

#ifdef DEBUG
  printf("[OK] ARP reply structure (struct ether_arp) "
	 "constructed successfully\n");
#endif


  /* ====================================================================== */

  /* SEND THE FRAME */

  int err = sendto(sockfd, &reply, sizeof(reply), 0,
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



/* Listens to an ARP frame

   sockfd: the socket file descriptor
   result: the parsed ARP frame

   Returns 0 if an ARP answer was found, -1 otherwise.
 */
int listen_arp_frame(int sockfd, struct ether_arp *result)
{
  int count = 0;
  
  while (recv(sockfd, result, sizeof(struct ether_arp), 0) && count < 20) {
    /* skip to the next frame if it's not an ARP REPLY */
    if (ntohs (result->arp_op) != ARPOP_REPLY) {
      ++count;
      continue;
    }

#ifdef DEBUG
    /* if it is an ARP reply */
    printf("[OK] Reply frame received\n");
    printf("Hardware type: %d\n", ntohs(result->arp_hrd));
    printf("Protocol type: %d\n", result->arp_pro);
    printf("Hardware size: %d\n", result->arp_hln);
    printf("Protocol size: %d\n", result->arp_pln);
    printf("Operation: %d\n", ntohs(result->arp_op));

    printf("Sender hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    	 result->arp_sha[0],result->arp_sha[1],result->arp_sha[2],
    	 result->arp_sha[3],result->arp_sha[4],result->arp_sha[5]);

    printf("Sender protocol address: %d.%d.%d.%d\n",
	   result->arp_spa[0],result->arp_spa[1],
	   result->arp_spa[2],result->arp_spa[3]);

    printf("Target hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    	 result->arp_tha[0],result->arp_tha[1],result->arp_tha[2],
    	 result->arp_tha[3],result->arp_tha[4],result->arp_tha[5]);

    printf("Target protocol address: %d.%d.%d.%d\n",
	   result->arp_tpa[0],result->arp_tpa[1],
	   result->arp_tpa[2],result->arp_tpa[3]);
#endif
    return 0;
    
  }
#ifdef DEBUG
  printf("[FAIL] No frame received\n");
#endif
  return -1;
}


