#define FLSTRSZ 256
#define OFSZ 256
#define IFSZ 64
#define PCAP_SAVEFILE "./capture.pcap"

typedef struct args {
    char fltstr[FLSTRSZ];
    char outfile[OFSZ];
    char ifname[IFSZ];
	int count;
} args_t;

args_t parse_args(int argc, char **argv);
