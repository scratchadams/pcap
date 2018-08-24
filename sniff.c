#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define ETH_SIZE 14

pcap_t * handle_setup(char *dev, int size, int promisc, int timeout);
int filter(pcap_t *handle, char *exp, char *dev);

struct ip* ip_header(const u_char *packet);
struct ether_header* eth_header(const u_char *packet);
struct ether_arp* arp_header(const u_char *packet);
struct tcphdr* tcp_header(const u_char *packet, int h_len);

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet);

int main(int argc, char *argv[]) {
    int iflag = 0;
    int nflag = 0;
    int packet_number = 5;
    int opt;

    const u_char *packet;
    struct pcap_pkthdr header;
    char *dev;

    while((opt = getopt(argc, argv, "i:n:")) !=-1) {
        switch(opt) {
            case 'i':
                iflag = 1;
                dev = strdup(optarg);
                break;
            case 'n':
                nflag = 1;
                packet_number = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-i interface] [-n number of packets]\n",
                        argv[0]);
                exit(-1);
        }
    }

    if((!nflag) && (!iflag)) {
        fprintf(stderr, "Usage: %s [-i interface] [-n number of packets]\n", 
                argv[0]);
        exit(-1);
    }

    pcap_t *handle = handle_setup(dev, BUFSIZ, 1, 1000);
    if(!handle) {
        printf("fail\n");
    }
    //printf("result: %d\n", sniff(dev, BUFSIZ, 1, 1000));
    //printf("filter result: %d\n", filter(handle, "port 23", dev));

    //packet = pcap_next(handle, &header);
    
    /*if(nflag == 1) {
        filter(handle, argv[2], dev);
    }*/
    pcap_loop(handle, packet_number, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

pcap_t * handle_setup(char *dev, int size, int promisc, int timeout) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev, size, promisc, timeout, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return NULL;
    }
    return handle;
}

int filter(pcap_t *handle, char *exp, char *dev) {

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    if(pcap_compile(handle, &fp, exp, 0, net) == -1) {
        fprintf(stderr, "couldn't parse filter %s: %s\n", 
                exp, pcap_geterr(handle));

        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", 
                exp, pcap_geterr(handle));

        return 2;
    }
}

void mac_str(const u_char *i_mac, char *mac, int size) {

    snprintf(mac, size, "%02x:%02x:%02x:%02x:%02x:%02x\0",
            i_mac[0], i_mac[1], i_mac[2], i_mac[3], i_mac[4], i_mac[5]);

    return;
}

void arp_ipstr(const u_int8_t *ip, char *buf, int size) {

    snprintf(buf, size, "%u.%u.%u.%u\0", ip[0], ip[1], ip[2], ip[3]);

    return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet) {

    const struct ether_header *ethernet = NULL;
    const struct ip *ip_h = NULL;
    const struct tcphdr *tcp_h = NULL;
    const struct ether_arp *arp_h = NULL;

    char *src, *dst;
    char s_mac[25], d_mac[25], s_ip[25], d_ip[25];
    int s_port, d_port;
    

    int is_tcp = 0;
    int is_ip = 0;
    int is_arp = 0;

    ethernet = (struct ether_header*)(packet);
    
    printf("%x\n", ETHERTYPE_IP);
    switch(ntohs(ethernet->ether_type)) {
        case ETHERTYPE_IP:
            ip_h = ip_header(packet);
            is_ip = 1;
            break;
        case ETHERTYPE_ARP:
            arp_h = arp_header(packet);
            is_arp = 1;
            break;
        default:
            printf("Not an IP packet\n");
            break;
    }

    if(is_arp) {
        mac_str(arp_h->arp_sha, s_mac, sizeof(s_mac));
        mac_str(arp_h->arp_tha, d_mac, sizeof(d_mac));
        
        arp_ipstr(arp_h->arp_spa, s_ip, sizeof(s_ip));
        arp_ipstr(arp_h->arp_tpa, d_ip, sizeof(d_ip));

        printf("%s >>>> %s\n", s_mac, d_mac);
        printf("%s >>>> %s\n", s_ip, d_ip);
        return;
    }

    if(is_ip) {
        switch(ip_h->ip_p) {
            case IPPROTO_TCP:
                tcp_h = tcp_header(packet, (ip_h->ip_hl << 2));
                is_tcp = 1;
                break;
            default:
                printf("Not a TCP Packet\n");
                break;
        }
    }

    if(is_tcp) {
        src = strdup(inet_ntoa(ip_h->ip_src));
        dst = strdup(inet_ntoa(ip_h->ip_dst));

        printf("%s >>>> %s\n", src, dst);
        printf("--------------------------------------\n");
    }
    /*
    if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        //printf("Ethernet type hex: %x is an IP packet\n", 
        //        ethernet->ether_dhost[0]);i
        ip_h = ip_header(packet);
        tcp_h = tcp_header(packet, (ip_h->ip_hl << 2));

        src = strdup(inet_ntoa(ip_h->ip_src));
        dst = strdup(inet_ntoa(ip_h->ip_dst));
        s_port = ntohs(tcp_h->th_sport);
        d_port = ntohs(tcp_h->th_dport);

        printf("%s:%d >>> %s:%d\n",src, s_port, dst, d_port);
        printf("--------------------------------------\n");
    }*/

}

struct ip* ip_header(const u_char *packet) {
    struct ip *ip_h;

    ip_h = (struct ip*)(packet + ETH_SIZE);
    //printf("From: %s\n", inet_ntoa(ip_h->ip_src));
    //printf("To: %s\n", inet_ntoa(ip_h->ip_dst));
    return ip_h;
}

struct ether_arp* arp_header(const u_char *packet) {
    struct ether_arp *arp_h;

    arp_h = (struct ether_arp*)(packet + ETH_SIZE);
    return arp_h;
}

struct ether_header* eth_header(const u_char *packet) {
    struct ether_header *eth_h;

    eth_h = (struct ether_header *)(packet);
    return eth_h;
}

struct tcphdr* tcp_header(const u_char *packet, int h_len) {
    struct tcphdr *tcp_h;

    tcp_h = (struct tcphdr *)(packet + ETH_SIZE + h_len);
    return tcp_h;
}
