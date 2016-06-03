/* arp/arp.h */

#ifndef ARP_H_
#define ARP_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <netpacket/packet.h>
#include <netinet/ether.h>





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
int send_arp_request(int sockfd, int ifindex, struct sockaddr_in *ipaddr, unsigned char *macaddr, struct in_addr target_ip);


/* Sends an ARP reply

   sockfd: file descriptor of the socket
   ifindex: index of the network interface
   sender_ip: source IP address
   sender_mac: source MAC address
   target_ip: IP address to which the answer is destined
   target_mac: MAC address of the target

   The function returns 0 on success, or exits with EXIT_FAILURE.
 */
int send_arp_reply(int sockfd, int ifindex, struct sockaddr_in *sender_ip, unsigned char *sender_mac, struct in_addr target_ip, unsigned char *target_mac);


/* Listens to an ARP frame

   sockfd: the socket file descriptor
   result: the parsed ARP frame

   Returns 0 if an ARP answer was found, -1 otherwise.
 */
int listen_arp_frame(int sockfd, struct ether_arp *result);


struct args {
  unsigned char macaddr1[6];
  unsigned char macaddr2[6];
  struct sockaddr_in ip_addr1;
  struct sockaddr_in ip_addr2;
};

/* Redirects all ethernet traffic from one address to another.

   args: struct args, which contains the hardware and protocol
   addresses of the targets.

   Never returns (killed when the main thread terminates).
 */
void *redirect_traffic(void *args);


#endif /* ARP_H_ */
