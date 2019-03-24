#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void mac(const u_char* packets)
{
    struct ether_header *eh;
    //unsigned short ether_type;
    eh = (struct ether_header *) packets;
    printf("-----------------------------\n");
    printf("dmac:");
    for(int i = 0; i<=5 ;i++){
        printf("%02x", eh->ether_dhost[i]);
        if(i<=4)
            printf(":");
        if(i>=5)
            printf("\n");
        }

    printf("smac:");
    for(int i = 0; i<=5 ;i++){
        printf("%02x", eh->ether_shost[i]);
        if(i<=4)
            printf(":");
        if(i>=5)
            printf("\n");
        }

    switch(ntohs(eh->ether_type))
    {
        case ETHERTYPE_IP:
            printf("Next protocol : IP\n");
            break;

        case ETHERTYPE_ARP:
            printf("Next protocol : ARP\n");
            break;

        case ETHERTYPE_REVARP:
            printf("Next protocol : REVARP\n");
            break;

        default:
            printf("Not Support Protocol\n");
            break;
    }

    printf("-----------------------------\n");

}

void ip(const u_char* packets)
{
    struct iphdr *iph;
    iph = (struct iphdr *)(packets + sizeof(struct ether_header));

    printf("sip: %s\n",inet_ntoa(*(struct in_addr *)&iph->saddr));
    printf("dip: %s\n",inet_ntoa(*(struct in_addr *)&iph->daddr));


    switch((unsigned int)iph->protocol)
    {
        case 0:
            printf("Next protocol : Reserved\n");
            break;
        case 1:
            printf("Next protocol : ICMP\n");
            break;
        case 2:
            printf("Next protocol : IGMP\n");
            break;
        case 3:
            printf("Next protocol : GGP\n");
            break;
        case 6:
            printf("Next protocol : TCP\n");
            break;
        case 17:
            printf("Next protocol : UDP\n");
            break;
        default:
            printf("Not Support Protocol\n");
            break;
    }
    printf("-----------------------------\n");
}

void tcp(const u_char* packets)
{
    //struct iphdr * iph;
    //iph = (struct iphdr *)(packets + sizeof(struct ethhdr));

    struct tcphdr *tcph;
    //tcph = (struct tcphdr *)(packets + iph->ihl*4 + sizeof(struct ethhdr));
    tcph = (struct tcphdr *)(packets + sizeof(struct iphdr) + sizeof(struct ethhdr));
    printf("sport: %u\n",ntohs(tcph->th_sport));
    printf("dport: %u\n",ntohs(tcph->th_dport));

    const u_int8_t* http;
    http = (packets + sizeof(struct tcphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));

    if(ntohs(tcph->th_dport) == 80 || ntohs(tcph->th_sport) == 80)
        printf("http data: %.*s\n",16, http);

    printf("-----------------------------\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  int i = 0;
  while (i < 10) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    mac(packet);
    ip(packet);
    tcp(packet);

    ++i;
  }

  pcap_close(handle);
  return 0;
}
