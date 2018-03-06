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
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define IP_ADDR_LEN 4

int init_arp(sr_arp_hdr_t* arp_hdr, uint8_t* mac_addr, struct sr_if* iface, uint8_t msg, uint32_t dip);
int arp_hst_cnv(sr_arp_hdr_t* arp_hdr);
int send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_req, struct sr_if* iface);
int sr_handle_arp(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_if* iface);
int process_arp_queue(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_arpreq* req_q);

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

struct sr_if *get_interface_from_ip(struct sr_instance *sr, uint32_t ip_addr) {
	struct sr_if *curr_interface = sr->if_list;
	struct sr_if *dest_interface = NULL;
	while(curr_interface) {
		if (ip_addr == curr_interface->ip) {
			dest_interface = curr_interface;
			break;
		}
		curr_interface = curr_interface->next;
	}
	return dest_interface;
}

void send_icmp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* rec_interface/* lent */,
        uint8_t icmp_type, uint8_t icmp_code, struct sr_if *dest_interface) {

	int header_len = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t);
	int outgoing_len;
	if (icmp_type == 0x00) {
		outgoing_len = len;
	} else {
		outgoing_len = header_len;
	}

	uint8_t *icmp_send_packet = (uint8_t *) malloc(outgoing_len);
	memset(icmp_send_packet, 0, sizeof(uint8_t) * outgoing_len);

	sr_ethernet_hdr_t *org_eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t *org_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	sr_icmp_hdr_t *icmp_send_hdr = (sr_icmp_hdr_t *)(icmp_send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	sr_ip_hdr_t *ip_send_hdr = (sr_ip_hdr_t *)(icmp_send_packet + sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t *eth_send_hdr = (sr_ethernet_hdr_t *)icmp_send_packet;

	struct sr_if *outgoing_interface = sr_get_interface(sr, rec_interface);
	uint32_t source_ip = outgoing_interface->ip;
	if (dest_interface) {
		source_ip = dest_interface->ip;
	}

	if (icmp_type == 0x00) {
		memcpy(icmp_send_hdr, (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)),
				outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	}
	/*else {
		//memcpy(icmp_send_hdr->****, org_ip_hdr, ICMP_DATA_SIZE);
	}*/

	icmp_send_hdr->icmp_type = icmp_type;
	icmp_send_hdr->icmp_code = icmp_code;
	icmp_send_hdr->icmp_sum = 0;
	if (icmp_type == 0x00) {
		icmp_send_hdr->icmp_sum = cksum(icmp_send_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	} else {
		icmp_send_hdr->icmp_sum = cksum(icmp_send_hdr, sizeof(sr_icmp_hdr_t));
	}

	memcpy(ip_send_hdr, org_ip_hdr, sizeof(sr_ip_hdr_t));
	ip_send_hdr->ip_dst = org_ip_hdr->ip_src;
	ip_send_hdr->ip_src = source_ip;
	ip_send_hdr->ip_p = ip_protocol_icmp;
	ip_send_hdr->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
	ip_send_hdr->ip_ttl = INIT_TTL;
	ip_send_hdr->ip_sum = 0;
	ip_send_hdr->ip_sum = cksum(ip_send_hdr, sizeof(sr_ip_hdr_t));

	memcpy(eth_send_hdr->ether_shost, outgoing_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(eth_send_hdr->ether_dhost, org_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
	eth_send_hdr->ether_type = htons(ethertype_ip);
	sr_send_packet(sr, icmp_send_packet, outgoing_len, rec_interface);
	free(icmp_send_packet);
	return;
}

void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/*Sanity Check*/
	if (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
		fprintf(stderr, "IP Packet not long enough.");
		return;
	}

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	uint16_t original_checksum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	uint16_t new_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
	if (original_checksum != new_checksum) {
		ip_hdr->ip_sum = original_checksum;
		fprintf(stderr, "IP Header checksum failed.");
		return;
	} else {
		ip_hdr->ip_sum = new_checksum;
	}

	struct sr_if *dest_interface = get_interface_from_ip(sr, ip_hdr->ip_dst);
	if (dest_interface) {
		if (ip_hdr->ip_p == ip_protocol_icmp) {
			/*Sanity Check*/
			if (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) > len) {
				fprintf(stderr, "ICMP Packet not long enough.");
				return;
			}

			original_checksum = icmp_hdr->icmp_sum;
			icmp_hdr->icmp_sum = 0;
			new_checksum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
			if (original_checksum != new_checksum) {
				icmp_hdr->icmp_sum = original_checksum;
				fprintf(stderr, "ICMP Header checksum failed.");
				return;
			} else {
				icmp_hdr->icmp_sum = new_checksum;
			}

			if (icmp_hdr->icmp_type != 8) {
				fprintf(stderr, "Not echo request.");
				return;
			}

			/*Send an echo reply back*/
			send_icmp_packet(sr, packet, len, interface, 0x00, 0x00, dest_interface);
			return;
		} else { /*Not an ICMP Packet*/
			send_icmp_packet(sr, packet, len, interface, 3, 3, dest_interface);
			return;
		}
	} else { /*Packet not for one of my interfaces*/
		if (ip_hdr->ip_ttl <= 1) {
			fprintf(stderr, "TTL Expired");
			send_icmp_packet(sr, packet, len, interface, 11, 0, NULL);
			return;
		}

		struct sr_rt *next_hop = NULL;
		struct sr_rt *routing_table_node = sr->routing_table;
		while(routing_table_node) {
			if ((routing_table_node->dest.s_addr && routing_table_node->mask.s_addr)
					== (ip_hdr->ip_dst && routing_table_node->mask.s_addr)) {
				if (!next_hop || (routing_table_node->mask.s_addr > next_hop->mask.s_addr)) {
					next_hop = routing_table_node;
				}
			}
			routing_table_node = routing_table_node->next;
		}

		if(!next_hop) {
			fprintf(stderr, "Couldn't find match in routing table.");
			send_icmp_packet(sr, packet, len, interface, 3, 0, NULL);
			return;
		}

		ip_hdr->ip_ttl--;
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

		struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), next_hop->gw.s_addr);
		if(!next_hop_mac) {
			fprintf(stderr, "ARP Cache entry not found.");
			struct sr_arpreq *queued_arp_req = sr_arpcache_queuereq(&(sr->cache), next_hop->gw.s_addr, packet, len, next_hop->interface);
			handle_arpreq(sr, queued_arp_req);
			return;
		}

		sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
		memcpy(ethernet_hdr->ether_shost, sr_get_interface(sr, next_hop->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
		memcpy(ethernet_hdr->ether_dhost, next_hop_mac->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
		free(next_hop_mac);
		sr_send_packet(sr, packet, len, sr_get_interface(sr, next_hop->interface)->name);
		return;
	}
}

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

    if (ethertype(packet) == ethertype_arp) {
        printf("Arp type\n");
        void* arp_offset = packet + sizeof(sr_ethernet_hdr_t);
        sr_arp_hdr_t * arphdr = (sr_arp_hdr_t *) (arp_offset);


        /* Sanity check: meets length */
        if (sizeof(*arphdr) < (len - sizeof(sr_ethernet_hdr_t))) {
            printf("Error in size\n");
            return;
        }

        if(sr_handle_arp(sr, arphdr, our_interface)){
            printf("ARP packet handling failure.\n");
        }


    }

    if (ethertype(packet) == ethertype_ip) {
	  handle_ip_packet (sr, packet, len, interface);
  }

  }




/*
 *Handles ARP packets from sr_handle packet. Assumes: Sanity check.
 * ARP Requests: If MAC matches us, call send_arp_reply
 * ARP Reply: Add MAC to arp cache, send all packets in queue waiting on this request.
 * Return 0 on success, 1 on failure
 * referred to: https://tools.ietf.org/html/rfc826
 */
int sr_handle_arp(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_if* iface)
{
    /*Convert to host byte order*/
    printf(" properly enter handle arp\n");
    arp_hst_cnv(arp_hdr);

    /*Check if the sender_ip is in our ARP cache, if it is, update hardware address with sender info*/
    /*If not in cache, and target IP is us, add to ARP cache*/
    struct sr_arpreq * req_q;
    req_q = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    printf(" properly call cache insert\n");
    /*If there are any packets waiting on this ARP, req_q hold them.  If none, req_q will be null*/



    /* Case 1: Request */
    /*Send back a reply*/
    if (arp_hdr->ar_op == arp_op_request) {
        printf("ARP request received.\n");
        send_arp_reply(sr, arp_hdr, iface);

    }
        /* Case 2: Reply */
        /*iterate through all the sr_arpreq's waiting on this MAC, if no requests (req_q == NULL) drop packet*/
    else if (arp_hdr->ar_op == arp_op_reply && req_q) {
        printf("ARP reply received.\n");
        process_arp_queue(sr, arp_hdr, req_q);
    }

    return 0;
}

int init_arp(sr_arp_hdr_t* arp_hdr, uint8_t* mac_addr, struct sr_if* iface, uint8_t msg, uint32_t dip)
{
    arp_hdr->ar_hrd = arp_hrd_ethernet;
    arp_hdr->ar_pro = ethertype_arp;
    arp_hdr->ar_tip = dip;
    arp_hdr->ar_sip = iface->ip;
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IP_ADDR_LEN ;

    /* put the mac addresses VALUES in the arp header */
    memcpy((void*)arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
    memcpy((void*)arp_hdr->ar_tha, mac_addr, ETHER_ADDR_LEN * sizeof(uint8_t));

    arp_hdr->ar_op = msg;

    return 0;
}
/*Per IBM resource, network bytes are always big endian, convert data other than MAC and IP addrs*/
int arp_ntwk_cnv(sr_arp_hdr_t* arp_hdr)
{
    arp_hdr->ar_hrd = htons(arp_hdr->ar_hrd);
    arp_hdr->ar_op = htons(arp_hdr->ar_op);
    arp_hdr->ar_pro = htons(arp_hdr->ar_pro);
    return 0;
}

/* Convert network ARP header byte order to host byte order*/
int arp_hst_cnv(sr_arp_hdr_t* arp_hdr)
{
    arp_hdr->ar_hrd = ntohs(arp_hdr->ar_hrd);
    arp_hdr->ar_op = ntohs(arp_hdr->ar_op);
    arp_hdr->ar_pro = ntohs(arp_hdr->ar_pro);
    printf(" properly exit hst_cnv\n");
    return 0;
}

/**
 * Creates ethernet frame and arp header to hold message
 * @param sr - router instance
 * @param msg - arp msg
 * @param mac_addr  - dest mac
 * @param dip - dest IP
 * @param iface - router interface for this message
 * @return 0 on success, 1 failure
 */
int send_arp(struct sr_instance* sr, uint8_t msg, uint8_t* mac_addr, uint32_t dip, struct sr_if* iface)
{

    uint8_t * packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    unsigned int len = (unsigned int) (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof( sr_ethernet_hdr_t));

    /* put the mac addresses VALUES in the ethernet header */
    memcpy((void*)eth_hdr->ether_dhost, mac_addr, ETHER_ADDR_LEN * sizeof(uint8_t));
    memcpy((void*)eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
    
    eth_hdr->ether_type = ethertype_arp;
    /* convert for ntwk order */
    eth_hdr->ether_type = htons(eth_hdr->ether_type);


    init_arp(arp_hdr, mac_addr, iface, msg, dip);

    arp_ntwk_cnv(arp_hdr);

    printf("Sending arp pckt \n");
    print_hdrs(packet, len);
    int success = sr_send_packet(sr, packet, len, iface->name);
    if(success == -1){
        fprintf(stderr, "ARP packet failure.\n");
    }
    printf("sr packet arp pckt success: %d \n", success);
    /*reverse the byte order for packet length*/
    free(packet);

    return 0;
}

/*Called when incoming packet is an arp request for router's interface*/
int send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_req, struct sr_if* iface)
{
    send_arp(sr, arp_op_reply, arp_req->ar_sha, arp_req->ar_sip, iface);
    return 0;
}

/*sends packets waiting on ARP request in the cache queue.  deletes data in request queue once packets are sent*/
int process_arp_queue(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_arpreq* req_q)
{
    assert(req_q);
    while(req_q->packets != NULL){
        struct sr_packet* packet = req_q->packets;
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)packet->buf;
        memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN * sizeof(uint8_t));
        sr_send_packet(sr, (uint8_t *)packet, packet->len, packet->iface);
        req_q->packets = req_q->packets->next;
    }

    sr_arpreq_destroy(sr->cache, req_q);
    return 0;
}

