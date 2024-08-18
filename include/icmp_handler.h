#ifndef ICMP_HANDLER_H_
#define ICMP_HANDLER_H_

#include <stdlib.h>
#include <stdint.h>

void generate_icmp_message(char *packet, int interface, size_t *length, uint8_t type, uint8_t code);
void process_icmp_reply(char *packet, size_t length, int interface);

#endif // ICMP_HANDLER_H_
