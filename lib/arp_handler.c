#include "arp_handler.h"
#include "lib.h"
#include "queue.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

// Caută o adresă IP în tabela ARP și returnează intrarea corespunzătoare
struct arp_table_entry *search_arp_entry(uint32_t ip) {
    for (int i = 0; i < arp_table_size; ++i) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

// Construiește și trimite o cerere ARP pentru a afla adresa MAC asociată unei adrese IP specifice
void send_arp_request(char *packet, uint32_t next_hop_ip, int interface) {
    // Adresa MAC destinată broadcast-ului pentru cererile ARP
    uint8_t mac_broadcast[6] = {255, 255, 255, 255, 255, 255};

    struct ether_header *eth_hdr = (struct ether_header *) packet;
    struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));

    // Inițializarea header-ului Ethernet pentru pachetul ARP
    memcpy(eth_hdr->ether_dhost, mac_broadcast, 6); // Adresa MAC destinație pentru broadcast.
    get_interface_mac(interface, eth_hdr->ether_shost); // Adresa MAC sursă.
    eth_hdr->ether_type = htons(ARP_TYPE); // Tipul de protocol este ARP.

    // Setează header-ul ARP.
    arp_hdr->htype = htons(1); // Tipul de hardware Ethernet.
    arp_hdr->ptype = htons(IPv4_TYPE); // Protocolul IP.
    arp_hdr->hlen = 6; // Lungimea adresei hardware (MAC).
    arp_hdr->plen = 4; // Lungimea adresei protocol (IP).
    arp_hdr->op = htons(ARP_REQUEST); // Operațiunea ARP request.
    arp_hdr->spa = inet_addr(get_interface_ip(interface)); // Adresa IP sursă.
    

    arp_hdr->spa = inet_addr(get_interface_ip(interface));
	get_interface_mac(interface, arp_hdr->sha);

	arp_hdr->tpa = next_hop_ip;
	memcpy(arp_hdr->tha, mac_broadcast, 6);

	// Adaugă header-ul ARP în pachet
	memcpy(packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	size_t length = sizeof(struct ether_header) + sizeof(struct arp_header);

	free(arp_hdr);

    // Trimite cererea ARP.
    send_to_link(interface, packet, length);
}

// Pregătește un pachet IPv4 pentru trimitere
void enqueue_packet_for_arp(uint32_t next_hop_ip, char *packet, size_t packet_len, int interface) {

    // Căutare în tabela ARP pentru a vedea dacă adresa MAC a următorului hop este deja cunoscută
    struct arp_table_entry *arp_entry = search_arp_entry(next_hop_ip);
    if (arp_entry) {
        // Adresa MAC a fost găsită în tabela ARP
        struct ether_header *eth_hdr = (struct ether_header *)packet;
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6); // Copiază adresa MAC în header-ul Ethernet
        send_to_link(interface, packet, packet_len); // Trimite pachetul pe rețea
    } else {
        // Dacă adresa MAC nu este cunoscută, pune pachetul în coadă
        struct ipv4_packet *queued_packet = malloc(sizeof(struct ipv4_packet));
        queued_packet->data = malloc(packet_len + 10);
        memcpy(queued_packet->data, packet, packet_len);
        queued_packet->length = packet_len;
        queued_packet->interface = interface;
        queued_packet->next_hop = next_hop_ip;
        queue_enq(arp_queue, queued_packet);
        arp_queue_len++;

        // Trimite o cerere ARP pentru a învăța adresa MAC.
        send_arp_request(packet, next_hop_ip, interface);
    }
}

// Adaugă o nouă intrare în tabela ARP
static void add_arp_entry(uint32_t ip_address, uint8_t *mac_addr) {
    // Caută o intrare existentă în tabela ARP pentru adresa IP furnizată
    struct arp_table_entry *entry = search_arp_entry(ip_address);
    if (entry) {
        // Dacă intrarea există deja, actualizează adresa MAC
        memcpy(entry->mac, mac_addr, 6);
    } else {
        // Dacă nu există o intrare pentru această adresă IP, crează una nouă
        struct arp_table_entry new_entry = {.ip = ip_address};
        memcpy(new_entry.mac, mac_addr, 6);
        arp_table[arp_table_size++] = new_entry;
    }
}

// Procesează coada de pachete așteptând adresa MAC
static void process_arp_queue() {
    // Creează o coadă temporară pentru a stoca pachetele care încă așteaptă
    queue temp_queue = queue_create();
    // Contorizează câte pachete au fost trimise
    int packets_forwarded = 0;

    // Iterează prin coada ARP până când aceasta este goală
    while (!queue_empty(arp_queue)) {
        struct ipv4_packet *waiting_packet = queue_deq(arp_queue); // Extrage un pachet din coadă
        // Accesează antetul Ethernet al pachetului
        struct ether_header *eth_head = (struct ether_header *)waiting_packet->data;

        // Caută o intrare în tabela ARP pentru IP-ul către care trebuie trimis pachetul
        struct arp_table_entry *arp_entry = search_arp_entry(waiting_packet->next_hop);
        if (arp_entry) {
            // Dacă există o intrare ARP, setează adresa MAC destinatar și trimite pachetul
            memcpy(eth_head->ether_dhost, arp_entry->mac, 6);
            send_to_link(waiting_packet->interface, waiting_packet->data, waiting_packet->length);
            free(waiting_packet->data);
            free(waiting_packet);
            packets_forwarded++;
        } else {
            // Dacă nu este găsită adresa MAC, pune pachetul înapoi în coada temporară
            queue_enq(temp_queue, waiting_packet);
        }
    }

    // Restabilește coada originală cu pachetele care încă așteaptă.
    while (!queue_empty(temp_queue)) {
        queue_enq(arp_queue, queue_deq(temp_queue));
    }
    // Eliberăm coada temporară.
    free(temp_queue);

    // Actualizează numărul de pachete în coada ARP
    arp_queue_len -= packets_forwarded;
}

// Procesează un răspuns ARP și actualizează tabela ARP
static void process_arp_reply(char *packet) {
    struct arp_header *arp_reply = (struct arp_header *)(packet + ETHER_HDR_SIZE);
    add_arp_entry(arp_reply->spa, arp_reply->sha);
    process_arp_queue();
}

// Procesează o cerere ARP primită, construind și trimițând un răspuns ARP
static void process_arp_request(char *packet, int interface, size_t length) {
    // Preia header-ul Ethernet și ARP din pachetul primit
    struct ether_header *eth_hdr = (struct ether_header *) packet;
    struct arp_header *arp_hdr = (struct arp_header *)(packet + ETHER_HDR_SIZE);

    // Actualizează operațiunea în antetul ARP la "replay"
    arp_hdr->op = htons(ARP_REPLY);

    memcpy(arp_hdr->tha, arp_hdr->sha, 6); // Setează adresa MAC destinație la sursa originală.
    get_interface_mac(interface, arp_hdr->sha); // Setează adresa MAC sursă la adresa MAC a interfeței.

    // În pregătirea răspunsului ARP, schimbăm adresele IP sursă și destinație
    uint32_t temp_ip = arp_hdr->spa; 
    arp_hdr->spa = inet_addr(get_interface_ip(interface)); 
    arp_hdr->tpa = temp_ip;

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6); // Setează adresa MAC destinație la sursa originală.
    get_interface_mac(interface, eth_hdr->ether_shost); // Setează adresa MAC sursă la adresa MAC a interfeței.

    // Trimite răspunsul ARP înapoi pe aceeași interfață de rețea
    send_to_link(interface, packet, length);
}

// Gestionează pachetele ARP, fie procesând cereri ARP, fie răspunsuri ARP
void handle_arp_packet(char *packet, int interface, size_t length) {
    struct arp_header *arp_hdr = (struct arp_header *)(packet + ETHER_HDR_SIZE);
    
    // Verifică tipul operațiunii din pachetul ARP
    if (ntohs(arp_hdr->op) == ARP_REQUEST) {
        // Dacă este o cerere ARP, procesează cererea
        process_arp_request(packet, interface, length);
    } else if (ntohs(arp_hdr->op) == ARP_REPLY) {
        // Dacă este un răspuns ARP, procesează răspunsul
        process_arp_reply(packet);
    }
}
