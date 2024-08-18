#ifndef IP_FORWARDING_H_
#define IP_FORWARDING_H_

#include <stdint.h>
#include <stddef.h>
#include "lib.h"
#include "trie.h"

// Structuri pentru gestionarea rutei și tabelei ARP
extern struct trie_node *route_trie;
extern u_int32_t route_count;

// Functii pentru a gestiona forwardarea pachetelor IP.
void forward_ipv4_packet(char *packet, int interface, size_t length);

#endif // IP_FORWARDING_H_
