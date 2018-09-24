#include "tunnel.hpp"
#include "PcapTools.hpp"

#include <FreeLTE.hpp>

#include <stdio.h>

uing32_t my_ip;
uint8_t my_mac[6];
uint8_t gw_mac[6];

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage : server (interface)\n");
        return 0;
    }

    open_and_init(argv[1], &my_ip, my_mac, gw_mac);

    estabilsh(my_ip, my_mac, gw_mac);

    pause();
}