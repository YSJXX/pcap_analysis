#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void ip(const u_char* packets);
void tcp(const u_char* packets);

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void ds(uint8_t a[],int x)
{
        if(x==1)
            printf("dmac:");
        if(x==2)
            printf("smac:");

    for(int i = 0; i<=5 ;i++)
    {
        printf("%02x", a[i]);
        if(i<=4)
            printf(":");
        if(i>=5)
            printf("\n");
     }
}
void mac(const u_char* packets)
{
    struct ether_header *eh;
    //unsigned short ether_type;
    eh = (struct ether_header *) packets;
    printf("****************************\n");
    ds(eh->ether_dhost,1);
    ds(eh->ether_shost,2);

    switch(ntohs(eh->ether_type))
    {
        case ETHERTYPE_IP:
            printf("Next protocol : IP\n\n");
            ip(packets);
            break;

        case ETHERTYPE_ARP:
            printf("Next protocol : ARP\n\n");
            ip(packets);
            break;

        case ETHERTYPE_REVARP:
            printf("Next protocol : REVARP\n\n");
            ip(packets);
            break;

        default:
            printf("Not Support Protocol\n\n");
            break;
    }


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
            printf("Next protocol : Reserved\n\n");
            tcp(packets);
            break;
        case 1:
            printf("Next protocol : ICMP\n\n");
            tcp(packets);
            break;
        case 2:
            printf("Next protocol : IGMP\n\n");
            tcp(packets);
            break;
        case 3:
            printf("Next protocol : GGP\n\n");
            tcp(packets);
            break;
        case 6:
            printf("Next protocol : TCP\n\n");
            tcp(packets);
            break;
        case 17:
            printf("Next protocol : UDP\n\n");
            tcp(packets);
            break;
        default:
            printf("Not Support Protocol\n\n");
            break;
    }
    printf("\n");
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

    printf("****************************\n");
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


  while (1) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    mac(packet);
    // ip(packet);
    //tcp(packet);

  }

  pcap_close(handle);
  return 0;
}
