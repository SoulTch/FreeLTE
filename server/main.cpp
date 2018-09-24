#include "tunnel.hpp"
#include "PcapTools.hpp"

#include <FreeLTE.hpp>

#include <netinet/ether.h>
#include <stdio.h>

uint32_t my_ip;
uint8_t my_mac[6];
uint8_t gw_mac[6];

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage : server (interface)\n");
        return 0;
    }

    open_and_init(argv[1], &my_ip, my_mac, gw_mac);

    printf("IP Address : %s\n", inet_ntoa(*(in_addr *)&my_ip));
    printf("MAC Address : %s\n", ether_ntoa((ether_addr *)my_mac));
    printf("GTW Address : %s\n", ether_ntoa((ether_addr *)gw_mac));

    establish(my_ip, my_mac, gw_mac);
    pause();
}