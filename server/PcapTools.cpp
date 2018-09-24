#include "PcapTools.hpp"

pcap_t *handle;
char errbuf[1000];

bool open_and_init(char *inf, uint32_t *serverIP, uint8_t *serverMac, uint8_t *gatewayMac) {
    handle = pcap_open_live(inf, BUFSIZ, 0, 1, errbuf);

	std::thread pingthread([&]() {
		for (int i = 0; i < 10; i++) {
			usleep(200000);
			system("ping -c 1 8.8.8.8 > dummy.o");
		}
		return;
	});

	const uint8_t *pkt;
	pcap_pkthdr *hdr;

	uint32_t start = time(NULL);

	while(load(&hdr, &pkt) && time(NULL) - start <= 2) {
		if (
			*(uint16_t *)(pkt + 12) == htons(0x0800) && 
			*(uint8_t *)(pkt + 14) == 0x45 && 
			*(uint8_t *)(pkt + 23) == 0x01 &&
			*(uint32_t *)(pkt + 30) == 0x08080808) {
				
			*serverIP = ntohl(*(uint32_t *)(pkt + 26));
			memcpy(serverMac, pkt + 6, 6);
			memcpy(gatewayMac, pkt, 6);

			pingthread.join();
			return true;
		}
	}

	pingthread.join();
	return false;
}

bool load(struct pcap_pkthdr **h, const uint8_t **p) {
	int res;
	while(!(res = pcap_next_ex(handle, h, p)));
	return res > 0;
}

bool sendp(uint8_t *t, int sz) {
    pcap_sendpacket(handle, (u_char *)t, sz);
    return true;
}