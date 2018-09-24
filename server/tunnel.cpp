#include "tunnel.hpp"


#define BUFFER_SIZE 100
#define THREAD_COUNT 4

uint32_t mip;
uint8_t smac[6];
uint8_t dmac[6];

Squeue<std::pair<const uint8_t *, int> > q;
std::queue<uint16_t> prq;
std::map<std::pair<uint32_t, uint16_t>, std::pair<uint16_t, std::chrono::system_clock::time_point> > smap;
std::pair<uint32_t, uint16_t> pmap[70000];
boost::shared_mutex mtx;

template <typename T>
T add(T a, T b) {
    return a + b;
}

uint16_t get_port(uint32_t sip, uint16_t sprt, uint32_t seq, uint32_t ack) {
    std::pair<uint32_t, uint16_t> addr(sip, sprt);
    boost::upgrade_lock<boost::shared_mutex> lock(mtx);
    if (smap.find(addr) != smap.end()) {
        auto &t = smap[addr];
        t.second = std::chrono::system_clock::now();
        return t.first;
    } else {
        boost::upgrade_to_unique_lock< boost::shared_mutex> ulock(lock);
        uint16_t nport = 0;
        if (prq.size() < 50) {
            std::chrono::system_clock::time_point cur = std::chrono::system_clock::now();
            for (auto it = smap.begin(); it != smap.end();) {
                if (cur - it->second.second > std::chrono::hours(1)) {
                    prq.push(it->second.first);
                    smap.erase(it++);
                } else {
                    it++;
                }
            }

            if (prq.size() < 50) {
                // TODO :: ERROR
            }
        }

        nport = prq.front();
        prq.pop();

        smap[addr] = std::make_pair(nport, std::chrono::system_clock::now());
        pmap[nport] = std::make_pair(sip, sprt);
        return nport;
    }
}

std::pair<uint32_t, uint16_t> get_addr(uint16_t port) {
    return pmap[port];
}

void ip_checksum(struct ip *t) {
    t->ip_sum = 0;

    uint32_t r = 0;
    for (uint16_t *p = (uint16_t *)t; p < (uint16_t *)t + t->ip_hl * 2; p++) {
        r += ntohs(*p);
    }

    t->ip_sum = htons(~((r & 0xffff) + (r >> 16)));
}

void tcp_checksum(struct tcphdr *t) {

}

void tunneling() {
    const uint8_t *pkt;
	pcap_pkthdr *hdr;

    while(true) {
        load(&hdr, &pkt);
        q.push(std::make_pair(pkt, (int)(hdr->len)));
    }
}

void handler() {
    uint8_t buf[2000];
    while(true) {
        auto t = q.pop();

        uint8_t *p = (uint8_t *)t.first;
        int sz = t.second;
        if (sz < 54) continue;

        memcpy(buf + 100, p, sz);
        
        p = buf + 100;
        struct ether_header *hdr_eth = (struct ether_header *)p; 
        if (ntohs(hdr_eth->ether_type) != ETHERTYPE_IP) continue;

        p += sizeof(struct ether_header);
        struct ip *hdr_ip = (struct ip *)p; 
        if (hdr_ip->ip_p != IPPROTO_TCP && hdr_ip->ip_p != IPPROTO_UDP) continue;
        
        p += (hdr_ip->ip_hl * 4);
        struct tcphdr *hdr_tcp = (struct tcphdr *)p;
        uint16_t prt = ntohs(hdr_tcp->th_dport);

        if (hdr_ip->ip_p == IPPROTO_TCP && prt == FORWARD_PORT) {
            p += (hdr_tcp->th_off * 4);
            struct ip *rhdr_ip = (struct ip *)p;

            p += (rhdr_ip->ip_hl * 4);
            struct tcphdr *rhdr_tcp = (struct tcphdr *)p;

            rhdr_tcp->th_sport = htons(get_port(ntohl(hdr_ip->ip_src.s_addr), ntohs(rhdr_tcp->th_sport), ntohl(hdr_tcp->th_seq), ntohl(hdr_tcp->th_ack)));
            
            if (rhdr_tcp->th_flags | TH_SYN) {
                p += 20;
                for (int i = 0; i < rhdr_tcp->th_off * 4 - 20;) {
                    switch(p[i]) {
                        case TCPOPT_EOL : i = 10000; break;
                        case TCPOPT_NOP : i++; break;
                        case TCPOPT_MAXSEG : 
                            *(uint16_t *)&p[i + 2] = htons(ntohs(*(uint16_t *)&p[i + 2]) - 50);
                        default : 
                            i += p[i + 1];
                    }
                }
            }
        } else if (REVERSE_PORT_START <= prt && prt <= REVERSE_PORT_END) {
            std::pair<uint32_t, uint16_t> addr = get_addr(prt);
            hdr_ip->ip_dst.s_addr = htonl(addr.first);
            hdr_tcp->th_dport = htons(addr.second);

            p = buf + 100 + sizeof(struct ether_header) - 20;
            memcpy(p, hdr_tcp, 20);
            struct tcphdr *rhdr_tcp = (struct tcphdr *)p;
            rhdr_tcp->th_seq = htonl(RESERVED_ACK);
            rhdr_tcp->th_ack = htonl(RESERVED_SYN);
            rhdr_tcp->th_off = 5;
            rhdr_tcp->th_sport = htons(FORWARD_PORT);

            p -= 20;
            struct ip *rhdr_ip = (struct ip *)p;
            rhdr_ip->ip_v = 4;
            rhdr_ip->ip_hl = 5;
            rhdr_ip->ip_tos = 0;
            rhdr_ip->ip_len = 0; // TODO : LEN
            rhdr_ip->ip_id = 0; // ??
            rhdr_ip->ip_off = htons(IP_DF);
            rhdr_ip->ip_ttl = 88;
            rhdr_ip->ip_p = IPPROTO_TCP;
            rhdr_ip->ip_dst.s_addr = htonl(addr.first);

            p -= sizeof(struct ether_header);
        } else {
            continue;
        }

        struct ether_header *fhdr_eth = (struct ether_header *)p;
        struct ip *fhdr_ip = (struct ip *)((uint8_t *)fhdr_eth + sizeof(struct ether_header));
        struct tcphdr *fhdr_tcp = (struct tcphdr *)((uint8_t *)fhdr_ip + fhdr_ip->ip_hl * 4);

        memcpy(fhdr_eth->ether_shost, smac, 6);
        memcpy(fhdr_eth->ether_dhost, dmac, 6);
        fhdr_eth->ether_type = htons(ETHERTYPE_IP);

        fhdr_ip->ip_src.s_addr = htonl(mip);
    }
}

bool establish(uint32_t _ip, uint8_t *_smac, uint8_t *_dmac) {
    mip = htonl(_ip);
    memcpy(smac, _smac, 6);
    memcpy(dmac, _dmac, 6);

    std::thread t(tunneling);

    for (int i = REVERSE_PORT_START; i <= REVERSE_PORT_END; i++) {
        prq.push(i);
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        std::thread s(handler);
    }

    std::thread(tunneling).detach();
    std::thread(handler).detach();
    return true;
}
