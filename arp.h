/* Satrap/arp.h */

#ifndef ARP_H_
#define ARP_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

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


/* Scans the subnet by sending ARP requests. If a reply is received,
   we know that the target is alive.

   sockfd: socket file descriptor
   ifindex: index of the interface
   ipaddr: local IP address
   macaddr: local hardware address
   netmask: local netmask

   Returns 0 when the scan is complete.
 */
int arp_scan(int sockfd, int ifindex, struct sockaddr_in *ipaddr, unsigned char *macaddr, struct sockaddr_in *netmask);


/* ARP man-in-the-middle attack.

   sockfd: socket file descriptor
   ifindex: index of the interface
   ipaddr: local IP address
   macaddr: local hardware address
   target1_ip: IP address of the first target
   target2_ip: IP address of the second target

   Never returns, has to be killed by the user.
 */
int arp_mitm(int sockfd, int ifindex, struct sockaddr_in *ipaddr, unsigned char *macaddr, struct in_addr *target1_ip, struct in_addr *target2_ip);



#endif /* ARP_H_ */
