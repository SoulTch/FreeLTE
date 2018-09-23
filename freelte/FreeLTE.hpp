#ifndef _FREE_LTE_H__
#define _FREE_LTE_H__


#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#define FORWARD_PORT 21892
#define REVERSE_PORT_START  34455
#define REVERSE_PORT_END    54455

#define RESERVED_SYN 0x26182930
#define RESERVED_ACK 0x26182930

void finish(uint8_t *);
#endif