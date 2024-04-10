#include <pcap.h>
#include <signal.h>
#include <stdio.h>

#include "headers/ethhdr.h"
#include "headers/iphdr.h"
#include "headers/tcphdr.h"
#include "headers/udphdr.h"

struct RxPacket {
    struct EthHdr *ethhdr{nullptr};
    struct IpHdr *iphdr{nullptr};
    struct TcpHdr *tcphdr{nullptr};
    struct UdpHdr *udphdr{nullptr};
};

void usage() {
    printf("usage: sudo ./pcap-study <interface>\n");
    printf("example: sudo ./pcap-study eth0\n");
}

void intHandler(int sig) {
    signal(sig, SIG_IGN);
    printf("==============================================================================================|\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    signal(SIGINT, intHandler);

    char *interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    printf("|===============================================================================================|\n");
    printf("|                   mac                   |                 ip                 |      port      |\n");
    printf("|===============================================================================================|\n");

    int cnt = 0;
    while (++cnt) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;

        // receive packet
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;

        // parsing
        RxPacket *rxPacket = new RxPacket;

        rxPacket->ethhdr = (EthHdr *)(packet);
        if (rxPacket->ethhdr->type() != EthHdr::ipv4)
            continue;

        rxPacket->iphdr = (IpHdr *)(packet + ETH_SIZE);
        if (rxPacket->iphdr->proto() != IpHdr::tcp)
            continue;

        rxPacket->tcphdr = (TcpHdr *)(packet + ETH_SIZE + rxPacket->iphdr->ipHdrSize());

        // printf mac
        uint8_t *srcMac = rxPacket->ethhdr->src();
        uint8_t *dstMac = rxPacket->ethhdr->dst();
        printf("| %02x", srcMac[0]);
        for (int i = 1; i < 6; i++)
            printf(":%02x", srcMac[i]);
        printf(" --> %02x", dstMac[0]);
        for (int i = 1; i < 6; i++)
            printf(":%02x", dstMac[i]);
        printf(" ");

        // printf ip
        uint32_t srcIp = rxPacket->iphdr->src();
        uint32_t dstIp = rxPacket->iphdr->dst();
        uint8_t srcIpArr[4], dstIpArr[4];
        for (int i = 0; i < 4; i++, srcIp >>= 8)
            srcIpArr[i] = srcIp & 0xff;
        for (int i = 0; i < 4; i++, dstIp >>= 8)
            dstIpArr[i] = dstIp & 0xff;
        char srcIpBuf[16], dstIpBuf[16];
        sprintf(srcIpBuf, "%d.%d.%d.%d", srcIpArr[0], srcIpArr[1], srcIpArr[2], srcIpArr[3]);
        sprintf(dstIpBuf, "%d.%d.%d.%d", dstIpArr[0], dstIpArr[1], dstIpArr[2], dstIpArr[3]);
        printf("| %15s -> %-15s ", dstIpBuf, srcIpBuf);

        // printf tcp
        uint16_t srcPort = rxPacket->tcphdr->srcport();
        uint16_t dstPort = rxPacket->tcphdr->dstport();
        printf("| %5d -> %-5d |\n", srcPort, dstPort);
    }

    return 0;
}