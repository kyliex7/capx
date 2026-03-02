#include "parse_args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

args_t parse_args(int argc, char **argv)
{
    int opt;
    args_t args;
    opterr = 0;

    while ((opt = getopt(argc, argv, "i:o:f:")) != -1) {
        switch (opt) {
        case 'o':
            if (optarg) {
                strncpy(args.outfile, optarg, OFSZ - 1);
                args.outfile[OFSZ - 1] = '\0';
            } else {
                strcpy(args.outfile, PCAP_SAVEFILE);
            }
            break;
        case 'i':
            if (optarg) {
                strncpy(args.ifname, optarg, IFSZ - 1);
                args.ifname[IFSZ - 1] = '\0';
            }
            break;
        case 'f':
            if (optarg) {
                strncpy(args.fltstr, optarg, FLSTRSZ - 1);
                args.fltstr[FLSTRSZ - 1] = '\0';
            }
            break;
        case '?':
            fprintf(stderr, "ERROR: invalid option: -%c\n", optopt);
            exit(-1);
        case ':':
            fprintf(stderr, "ERROR: option -%c requires an argument\n", optopt);
            exit(-1);
        }
    }

    return args;
}
