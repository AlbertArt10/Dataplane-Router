#ifndef _TRIE_H_
#define _TRIE_H_

#include <stdint.h>

// Structura unui nod din arborele trie pentru tabelul de rutare
struct trie_node {
        struct route_table_entry *route;
        struct trie_node *left, *right;
};

// Functie pentru crearea unui nou nod in arbore
struct trie_node *create_trie_node(void);

// Functie pentru inserarea unei noi intrari in arborele trie
void add_route(struct trie_node *root, struct route_table_entry *new_entry);

// Functie pentru cautarea unei adrese IP in arborele trie
struct trie_node *find_best_match(struct trie_node *root, uint32_t ip_address);

// Functie pentru eliberarea memoriei alocate pentru arborele trie
void free_trie(struct trie_node *root);

#endif /* _TRIE_H_ */
