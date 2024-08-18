#include "ip_forwarding.h"
#include "arp_handler.h"
#include "lib.h"
#include "protocols.h"
#include "icmp_handler.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

// Obtine urmatorul hop pentru o adresa IP de destinatie
struct route_table_entry *get_next_hop(uint32_t dest_ip)
{
	struct trie_node *node_found = find_best_match(route_trie, dest_ip);

	if (node_found != NULL)
		return node_found->route;
	else
		return NULL;
}

// Verifică și actualizează header-ul IPv4 al unui pachet primit
int check_and_update_ipv4_hdr(char *packet, int interface, size_t *length) {
    struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_HDR_SIZE);

    // Verifică Time To Live (TTL) și generează mesaj ICMP Time Exceeded
    if (ip_hdr->ttl <= 1) {
        // Tip 11: Time Exceeded, Cod 0: TTL expirat în tranzit
        generate_icmp_message(packet, interface, length, 11, 0);
    }
    
    // Salveaza si recalculează checksum-ul pentru header-ul IPv4
    uint16_t old_checksum = ip_hdr->check;
    ip_hdr->check = 0; // Zero înainte de calcul
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, IP_HDR_SIZE));
    
    // Compară checksum-ul vechi cu cel nou recalculat
    if (old_checksum != ip_hdr->check) {
        return -1;
    }

    // Decrementare TTL și recalculare checksum după modificare
	ip_hdr->ttl--;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, IP_HDR_SIZE));

    return 0;
}

// Forwardază pachetele IPv4 conform tabelei de rutare
void forward_ipv4_packet(char *packet, int interface, size_t length) {
    // Verifică header-ul IPv4 și actualizează TTL și checksum
    if (check_and_update_ipv4_hdr(packet, interface, &length) != 0) {
        return;
    }

    struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_HDR_SIZE);
    struct ether_header *eth_hdr = (struct ether_header *) packet;

    // Caută în tabela de rutare o rută către destinația pachetului
    struct route_table_entry *route = get_next_hop(ntohl(ip_hdr->daddr));

    // Dacă nu există o rută validă, generează un mesaj ICMP Destination Unreachable
    if (route == NULL) {
        generate_icmp_message(packet, interface, &length, 3, 0); // Cod 3 pentru Destination Unreachable
        // Reîncearcă să găsești ruta după generarea mesajului ICMP
        route = get_next_hop(ntohl(ip_hdr->daddr));
    }

    // Actualizează adresa MAC sursă în header-ul Ethernet
    get_interface_mac(route->interface, eth_hdr->ether_shost);
    
    // Pregătește pachetul pentru ARP
    enqueue_packet_for_arp(route->next_hop, packet, length, route->interface); 
}
