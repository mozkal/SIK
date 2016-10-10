#include "parameters.h"
#include "err.h"
#include <stdlib.h>
#include <stdio.h>

int ssh_enabled = SSH_DEFAULT;
int measure_t = MEASURE_DEFAULT;
int discover_t = DISCOVER_DEFAULT;
char *udp_port = UDP_PORT_DEFAULT;
char *telnet_port = TELNET_PORT_DEFAULT;
int telnet_t = TELNET_T_DEFAULT;

void read_parameters(int argc, char **argv) {
    int i = 1;

    while(i < argc) {
        if(argv[i][0] != '-')
            fatal("Illegal parameters");

        if(argv[i][1] == 's')
            ssh_enabled = 1;
        else {
            if(i + 1 >= argc)
                fatal("Illegal parameters");

            switch((int) argv[i][1]) {
                case 't': measure_t = atoi(argv[i + 1]); break;
                case 'T': discover_t = atoi(argv[i + 1]); break;
                case 'u': udp_port = argv[i + 1]; break;
                case 'U': telnet_port = argv[i + 1]; break;
                case 'v': telnet_t = atoi(argv[i + 1]); break;

                default: fatal("Illegal parameters");
            }
            ++i;
        }
        ++i;
    }
}