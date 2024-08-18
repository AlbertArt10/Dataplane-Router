#include "trie.h"
#include "lib.h"
#include <stdlib.h>
#include <arpa/inet.h>

// Functie pentru crearea unui nou nod in arbore
struct trie_node *create_trie_node(void)
{
	struct trie_node *node = malloc(sizeof(struct trie_node));

	node->route = NULL;
	node->left = NULL;
	node->right = NULL;

	return node;
}

// Functie pentru inserarea unei noi intrari in arborele trie
void add_route(struct trie_node *root, struct route_table_entry *new_entry)
{
	uint32_t prefix = ntohl(new_entry->prefix);
	uint32_t mask = ntohl(new_entry->mask);
	struct trie_node *current = root;

	// Pentru fiecare bit din prefix, parcurgem sau cream noduri in arbore
	while (mask) {
		if (prefix & (1 << 31)) { // Verificam daca bitul curent este 1
			if (!current->right)  // Dacă nodul drept nu exista, il cream
				current->right = create_trie_node();
			current = current->right;
		} else { // Bitul curent este 0
			if (!current->left)  // Daca nodul stang nu exista, il cream
				current->left = create_trie_node();
			current = current->left;
		}

		prefix <<= 1; // Treci la urmatorul bit din prefix
        mask <<= 1;   // Treci la urmatorul bit din masca
	}

	// Asociem intrarea din tabelul de rutare cu nodul curent
	current->route = new_entry;
}

// Functie pentru cautarea unei adrese IP in arborele trie
struct trie_node *find_best_match(struct trie_node *root, uint32_t ip_address)
{
	struct trie_node *current = root;
	struct trie_node *best_match = NULL;

	// Parcurgem arborele trie conform bitilor adresei IP
	while (current) {
        if (current->route)
            best_match = current; // Actualizeaza cel mai bun meci gasit

		// Alege directia pe baza bitului curent
        current = ip_address & (1 << 31) ? current->right : current->left;
        ip_address <<= 1; // Trece la urmatorul bit din adresa IP
    }

    return best_match;
}

// Functie pentru eliberarea memoriei alocate pentru arborele trie
void free_trie(struct trie_node *root)
{	
	if (!root) return;

	free_trie(root->left);
    free_trie(root->right);

	if (root->route)
		free(root->route);
	free(root);
}
