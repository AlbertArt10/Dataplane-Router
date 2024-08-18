# Tema 1 PCOM - Dataplane Router

## Descriere:

Implementare a dataplane-ului unui router în C/C++, incluzând procesul de dirijare IPv4, 
Longest Prefix Matching (LPM) cu trie, protocoale ARP și ICMP. Gestionarea pachetelor, 
actualizarea tabelei ARP, și generarea mesajelor ICMP sunt integrate pentru routing eficient.

Enunt Tema: https://pcom.pages.upb.ro/tema1/

Checker + schelet: https://gitlab.cs.pub.ro/pcom/homework1-public

## Procesul de dirijare (IPv4 Forwarding):

- Pachetele sunt inițial prelucrate prin functia forward_ipv4_packet(), unde TTL-ul este decrementat 
și checksum-ul este re-verificat și actualizat.
- Se folosește get_next_hop() pentru a determina următorul hop pe baza adresei destinație IPv4.
- Functia enqueue_packet_for_arp() este apelată pentru a gestiona transmiterea pachetelor atunci 
când adresa MAC a următorului hop este necunoscută.
- Dacă adresa MAC este cunoscută, header-ul Ethernet este actualizat și pachetul este trimis 
folosind functia send_to_link().


## Longest Prefix Match Eficient (Trie):

- Se creează un trie gol utilizând create_trie_node(). Trie-ul este o structură de arbore binar,
unde fiecare nod poate avea doi copii: stânga și dreapta, reprezentând bitul 0 sau 1 al prefixului
unei adrese IP.
- Funcția load_routing_table() citește tabela de rutare din fișier și folosește add_route() 
pentru a adăuga fiecare intrare în trie.
- Când se primește un pachet, adresa IP destinație este folosită pentru a găsi cel mai bun traseu 
prin funcția find_best_match().
- Căutarea în trie pentru LPM este mult mai rapidă decât căutarea liniară, mai ales 
când tabela de rutare devine mare.


## Protocolul ARP:

- Pachetele care necesită o adresă MAC necunoscută sunt plasate într-o coadă 'arp_queue'
prin functia enqueue_packet_for_arp().
- Când se primește un răspuns ARP, process_arp_reply() actualizează tabela ARP și 
procesează pachetele din coadă.
- Functia handle_arp_packet() distinge între cereri și răspunsuri ARP, procesându-le corespunzător.
- Functia send_arp_request() trimite solicitări ARP când este necesar.
- Functiile process_arp_queue() și add_arp_entry() gestionează actualizarea cache-ului ARP și 
trimiterea pachetelor care așteptau aceste adrese MAC.
- Caching-ul răspunsurilor ARP facilitează transmiterea rapidă a pachetelor viitoare 
către aceleași adrese.


## Protocolul ICMP:

- Functia generate_icmp_message() construiește mesaje ICMP pentru diferite situații, 
cum ar fi TTL expirat sau destinație inaccesibilă.
- Router-ul răspunde la "Echo request" cu "Echo reply", cu ajutorul funcției process_icmp_reply().
- Funcția update_ipv4_header() actualizează header-ul IP pentru mesajele ICMP care trebuie trimise 
înapoi la sursă.
- ICMP este de asemenea folosit pentru a notifica expeditorii când pachetele lor nu pot fi dirijate
corect sau atunci când TTL-ul pachetului a expirat.
