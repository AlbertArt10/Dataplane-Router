#ifndef ARP_HANDLER_H_
#define ARP_HANDLER_H_

#include "lib.h"
#include "protocols.h"
#include "queue.h"
#include <stdint.h>
#include <stdlib.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

// Declarație externă a variabilei pentru lungimea cozii ARP.
extern struct arp_table_entry arp_table[100];
extern uint32_t arp_table_size;
extern queue arp_queue;
extern uint32_t arp_queue_len;

// Structură pentru reprezentarea pachetelor IPv4
struct ipv4_packet {
	char *data; 
	size_t length;   
	int interface;    
	uint32_t next_hop; 
};

struct arp_table_entry *search_arp_entry(uint32_t ip);
void handle_arp_packet(char *packet, int interface, size_t length);
void enqueue_packet_for_arp(uint32_t next_hop_ip, char *packet, size_t packet_len, int interface);

#endif // ARP_HANDLER_H_
