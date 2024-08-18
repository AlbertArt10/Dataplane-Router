#include "lib.h"
#include "trie.h"
#include "queue.h"
#include "protocols.h"
#include "arp_handler.h"
#include "icmp_handler.h"
#include "ip_forwarding.h"

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

// Structuri pentru gestionarea rutei și tabelei ARP
struct trie_node *route_trie;
u_int32_t total_route;

struct arp_table_entry arp_table[100];
u_int32_t arp_table_size;

// Coada pentru pachete ce așteaptă adresa MAC prin ARP
queue arp_queue;
uint32_t arp_queue_len;

// Încarcă tabela de rutare și o adaugă in arborele trie
int load_routing_table(const char *filePath, struct trie_node *trieRoot) {
    FILE *file = fopen(filePath, "r");
    if (file == NULL) {
        return 0;
    }

    char buffer[64]; // Buffer pentru stocarea fiecărei linii citite
    int entryCount = 0; // Contor pentru numărul de intrări de rutare procesate

	// Citire linie cu linie din fișier
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        struct route_table_entry *entry = malloc(sizeof(struct route_table_entry));
        char *token;
        int index = 0;
        unsigned char *byteArray = (unsigned char *)entry;

        // Extrage fiecare parte a intrării de rutare
        token = strtok(buffer, " .");
        while (token != NULL && index < 13) { // Există 12 segmente plus interfața
            if (index < 12) { // Primele 12 valori sunt octeții adresei IP și ai măștii
				for (int i = index; i < index + 1 && token; i++) {
					// Convertirea stringului în valoare numerică
        			byteArray[i] = (unsigned char)atoi(token);
    			}

            } else { // Ultimul segment este interfața
                entry->interface = atoi(token);
            }
            token = strtok(NULL, " .");
            index++;
        }

        add_route(trieRoot, entry); // Inserează intrarea în trie
        entryCount++;
    }

    fclose(file);
    return entryCount; // Numărul de intrări adăugate
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN]; // Buffer pentru stocarea pachetelor recepționate

	// Inițializare tabela ARP
	arp_table_size = 0;

	// Inițializare trie pentru tabela de rutare
	route_trie = create_trie_node();
	// Încărcare tabela de rutare
	total_route = load_routing_table(argv[1], route_trie);

	// Inițializare coadă pentru pachetele ARP în așteptare
	arp_queue = queue_create();
	arp_queue_len = 0;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Ciclu principal pentru prelucrarea pachetelor
	while (1) {
		int interface;
		size_t length;

		// Recepe un pachet de pe orice interfață disponibilă
		interface = recv_from_any_link(buf, &length);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		// Determină tipul protocolului încapsulat în antetul Ethernet
		if (ntohs(eth_hdr->ether_type) == IPv4_TYPE) {
			struct iphdr *ipv4_hdr = (struct iphdr *) (buf + ETHER_HDR_SIZE);

			// Verifică dacă destinația pachetului este chiar routerul
			if (ipv4_hdr->daddr == inet_addr(get_interface_ip(interface)))
				// Procesează răspunsul ICMP
				process_icmp_reply(buf, length, interface);
			else
				// Altfel, direcționează pachetul conform tabelei de rutare
				forward_ipv4_packet(buf, interface, length);
		} else if (ntohs(eth_hdr->ether_type) == ARP_TYPE)
				// Procesează pachetele ARP (solicitări și răspunsuri)
    			handle_arp_packet(buf, interface, length);
	}

	// Elibereaza memoria alocata
	free_trie(route_trie);

	return 0;
}
