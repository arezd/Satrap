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


#define DEBUG



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

int send_arp_reply(int sockfd, int ifindex, struct sockaddr_in *sender_ip, unsigned char *sender_mac, struct in_addr target_ip, unsigned char *target_mac);

#endif /* ARP_H_ */
