#ifndef _PCAP_TOOLS_H__
#define _PCAP_TOOLS_H__

#include <pcap.h>
#include <thread>
#include <arpa/inet.h>
#include <memory.h>
#include <unistd.h>

extern pcap_t *handle;

bool open_and_init(char *inf, uint32_t *, uint8_t *, uint8_t *);
bool load(struct pcap_pkthdr **, const uint8_t **);
bool sendp(uint8_t *, int);

#endif