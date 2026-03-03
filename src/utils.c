#include <stdlib.h>
#include <stdio.h>

void usage(char *progname)
{
	fprintf(stderr, "Usage: %s -i interface_name -n count -f bpf_filter -o outfile", progname);
	exit(-1);
}
