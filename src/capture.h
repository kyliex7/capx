#include <pcap/pcap.h>

typedef struct callback_data {
    int pktcnt;
    int link_hdr_len;
	pcap_dumper_t *dumpfile;
} callback_data_t;

int get_link_hdr_len(int datalink_type);
void loop_callback(u_char *user, const struct pcap_pkthdr *header,
                   const u_char *packet_data);
