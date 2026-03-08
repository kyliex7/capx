/*
 * DO WHAT THE FUCK YOU WANT WITH THIS
 */
#include "capture.h"
#include "parse_args.h"
#include "utils.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *g_capdev = NULL;
static pcap_dumper_t *g_dumper = NULL;

void sigint_handler(int sig)
{
    (void)sig;
    if (g_dumper)
        pcap_dump_close(g_dumper);
    if (g_capdev)
        pcap_breakloop(g_capdev);

    exit(1);
}

int main(int argc, char *argv[])
{
    // TODO: add -h
    if (argc < 2) {
        usage(argv[0]);
    }

    args_t args = parse_args(argc, argv);
    struct bpf_program fp;
    char *dev = args.ifname;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filename = args.outfile;

    signal(SIGINT, sigint_handler);

    /*
     *	  BUFSIZ: defined in stdio ( grep -R 'BUFSIZ' /usr/include/stdio.h )
     *	  1000 milliseconds timeout
     */
    if ((g_capdev = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf)) == NULL) {
        fprintf(stderr, "ERROR: opening device %s\n", errbuf);
        return -1;
    }

    printf("INFO: Listening on device: %s\n", dev);

    if (*args.fltstr) {
        if ((pcap_compile(g_capdev, &fp, args.fltstr, 0,
                          PCAP_NETMASK_UNKNOWN)) == -1) {
            fprintf(stderr, "ERROR: pcap_compile: %s\n", pcap_geterr(g_capdev));
            return -1;
        }
        if ((pcap_setfilter(g_capdev, &fp)) != 0) {
            fprintf(stderr, "ERROR: pcap_setfilter: %s\n",
                    pcap_geterr(g_capdev));
            return -1;
        }

        pcap_freecode(&fp);
    }

    if ((g_dumper = pcap_dump_open(g_capdev, filename)) == NULL) {
        fprintf(stderr, "ERROR: opening dumpfile: %s\n", pcap_geterr(g_capdev));
        return -1;
    }
    printf("INFO: writing dump data do %s\n", filename);

    const int datalink_type = pcap_datalink(g_capdev);
    callback_data_t cb_data = {.pktcnt = 0,
                               .link_hdr_len = get_link_hdr_len(datalink_type),
                               .dumpfile = g_dumper};

    int ret =
        pcap_loop(g_capdev, args.count, loop_callback, (u_char *)&cb_data);
    if (ret == PCAP_ERROR) {
        fprintf(stderr, "ERROR: pcap_loop: %s\n", pcap_geterr(g_capdev));
        return -1;
    } else if (ret == PCAP_ERROR_NOT_ACTIVATED) {
        fprintf(stderr, "ERROR: handle not activated\n");
        return -1;
    }

    pcap_dump_close(g_dumper);
    pcap_close(g_capdev);
    return 0;
}

void loop_callback(u_char *user, const struct pcap_pkthdr *header,
                   const u_char *pktdptr)
{
    callback_data_t *cb_data = (callback_data_t *)user;
    cb_data->pktcnt++;

    pcap_dumper_t *pd = cb_data->dumpfile;
    pcap_dump((u_char *)pd, header, pktdptr);

    pktdptr += cb_data->link_hdr_len;

    struct ip *iphdr = (struct ip *)pktdptr;
    // TODO: add ipv6 support
    if (iphdr->ip_v != 4)
        return;

    /*
     *	   since inet_ntoa() stores the result in static buffer, we need to
     *     manually store the results in dynamic buffer.
     */
    char pkt_srcip[INET_ADDRSTRLEN], pkt_dstip[INET_ADDRSTRLEN];

    strcpy(pkt_srcip, inet_ntoa(iphdr->ip_src));
    strcpy(pkt_dstip, inet_ntoa(iphdr->ip_dst));

    int pkt_id = ntohs(iphdr->ip_id), // identification
        pkt_tos = iphdr->ip_tos,      // type of service
        // pkt_len = ntohs(iphdr->ip_len), // total length
        pkt_hlen = iphdr->ip_hl; // header length

    pktdptr += (4 * pkt_hlen);
    int proto_type = iphdr->ip_p;
    const char *proto_name = (proto_type == IPPROTO_TCP)   ? "TCP"
                             : (proto_type == IPPROTO_UDP) ? "UDP"
                                                           : "ICMP";

    printf("[%05d] %-5d | %-15s -> %-15s | %-4s | TOS: 0x%02x | ",
           cb_data->pktcnt, pkt_id, pkt_srcip, pkt_dstip, proto_name, pkt_tos);

    switch (proto_type) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (struct tcphdr *)pktdptr;

        printf("FLAGS: %c%c%c%c%c%c | %5d -> %-5d",
               (tcp->th_flags & TH_URG) ? 'U' : '.',
               (tcp->th_flags & TH_ACK) ? 'A' : '.',
               (tcp->th_flags & TH_PUSH) ? 'P' : '.',
               (tcp->th_flags & TH_RST) ? 'R' : '.',
               (tcp->th_flags & TH_SYN) ? 'S' : '.',
               (tcp->th_flags & TH_FIN) ? 'F' : '.', ntohs(tcp->source),
               ntohs(tcp->dest));

        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = (struct udphdr *)pktdptr;
        printf("LEN: %-8d | %5d -> %-5d", ntohs(udp->len), ntohs(udp->source),
               ntohs(udp->dest));
        break;
    }
    case IPPROTO_ICMP: {
        struct icmp *icmp = (struct icmp *)pktdptr;
        printf("TYPE: %-7d | CODE: %-3d       ", icmp->icmp_type,
               icmp->icmp_code);
        break;
    }
    default:
        printf("PROTO UNKNOWN");
    }

    printf("\n");
}

int get_link_hdr_len(int datalink_type)
{
    switch (datalink_type) {
    case DLT_EN10MB: // ethernet
        return 14;

    case DLT_NULL: // loopback (bsd & macos)
        return 4;

    case DLT_RAW: // raw ip
        return 0;

    case DLT_LINUX_SLL: // linux cooked capture
        return 16;

    case DLT_LINUX_SLL2: // linux cooked v2
        return 20;

    default:
        return 0; // unknown
    }
}
