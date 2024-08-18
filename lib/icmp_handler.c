#include "icmp_handler.h"
#include "ip_forwarding.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

// Actualizează header-ul IPv4 pentru pregătirea trimiterii unui mesaj ICMP
static void update_ipv4_header(struct iphdr *ip_header, int interface) {
    ip_header->daddr = ip_header->saddr; // Setează adresa IP de destinație
    ip_header->saddr = inet_addr(get_interface_ip(interface)); // Actualizează adresa IP sursă
    ip_header->ttl = 64; // Resetează TTL
    // Actualizează lungimea totală a pachetului
    ip_header->tot_len = htons(ntohs(ip_header->tot_len) + ICMP_HDR_SIZE + ICMP_PACKET_DATA_SIZE);
    ip_header->protocol = 1; // Setează protocolul la ICMP (valoare 1)

    // Recalculăm checksum-ul
    ip_header->check = 0;
    ip_header->check = htons(checksum((uint16_t *)ip_header, IP_HDR_SIZE));
}

// Construiește un header ICMP
static void build_icmp_header(struct icmphdr *icmp_header, uint8_t type, uint8_t code) {   
    memset(icmp_header, 0, ICMP_HDR_SIZE);
    icmp_header->type = type;
    icmp_header->code = code;
    icmp_header->checksum = 0;
    icmp_header->checksum = htons(checksum((uint16_t *)icmp_header, ICMP_HDR_SIZE));
}

// Modifică buffer-ul pentru a construi un mesaj ICMP
void generate_icmp_message(char *packet, int interface, size_t *length, uint8_t type, uint8_t code) {
    struct iphdr *ip_header = (struct iphdr *)(packet + ETHER_HDR_SIZE);
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + OFFSET_ICMP);
    char *icmp_data = malloc(ICMP_PACKET_DATA_SIZE);

    // Salvăm antetul IPv4 și următorii 64 de biți
    memcpy(icmp_data, ip_header, ICMP_PACKET_DATA_SIZE);

    // Actualizăm antetul IPv4
    update_ipv4_header(ip_header, interface);

    // Construim antetul ICMP
    build_icmp_header(icmp_header, type, code);

    memcpy(packet + OFFSET_ICMP_DATA, icmp_data, ICMP_PACKET_DATA_SIZE);

    free(icmp_data);

    // Actualizăm lungimea totală a buffer-ului
    *length += ICMP_HDR_SIZE + ICMP_PACKET_DATA_SIZE;
}

// Schimbă adresele IP sursă și destinație într-un header IP
static void swap_ip_addresses(struct iphdr *ip_header) {
    uint32_t address = ip_header->saddr;
    ip_header->saddr = ip_header->daddr;
    ip_header->daddr = address;
}

// Actualizează antetul unui mesaj ICMP pentru a genera un răspuns de tip Echo Reply
static void update_icmp_header(struct icmphdr *icmp_header) {
    icmp_header->type = 0;
    icmp_header->code = 0;
    icmp_header->checksum = 0;
    icmp_header->checksum = htons(checksum((uint16_t *)icmp_header, sizeof(struct icmphdr)));
}

// Procesează o cerere ICMP, generând un răspuns adecvat
void process_icmp_reply(char *packet, size_t length, int interface) {
    struct iphdr *ip_header = (struct iphdr *)(packet + ETHER_HDR_SIZE);
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + OFFSET_ICMP);

    // Verifică și resetează checksum-ul ICMP
    uint16_t received_checksum = icmp_header->checksum;
    icmp_header->checksum = 0;
    if (received_checksum != htons(checksum((uint16_t *)icmp_header, ICMP_HDR_SIZE))) {
        return;
    }

    // Schimbă adresele IP și recalculează checksum-ul IP
    swap_ip_addresses(ip_header);

    ip_header->check = 0; // Resetează checksum-ul
    ip_header->check = htons(checksum((uint16_t *)ip_header, IP_HDR_SIZE));

    // Actualizează antetul ICMP pentru răspuns și recalculează checksum-ul
    update_icmp_header(icmp_header);

    // Trimite pachetul mai departe
    forward_ipv4_packet(packet, interface, length);
}
