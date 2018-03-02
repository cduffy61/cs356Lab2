/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);



  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /*
   * 1. get the different parts of the ethernet header sr_protocol.h
   * 2. check if destination MAC is one of our interfaces, if not, drop packet
   * 3. check the CRC check sum if fail, drop packet
   *
   * if arp--if its arp req, write respnse, if reply, handle it
   * if TTL == O, reply ICMP TTL error to sender code 8
   */

  struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*)packet;
  if(htonl(len) < sizeof(sr_ethernet_hdr_t)){
	  fprintf(stderr, "Packet dropped, too small.\n");
      return;
  }
     struct sr_if *our_interface = sr_get_interface(sr, interface);

    /***
     * If ethertype of packet equals ARP
     */

    /**
     * if ethertype of packet equals IP
     */

    //else drop packet


}/* end sr_ForwardPacket */

int send_arp(struct sr_instance* sr, u_int8_t msg, uint8_t* mac_addr, uint32_t dip, struct sr_if* iface){
    
    return 0;
}

