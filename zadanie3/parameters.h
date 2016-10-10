#ifndef PARAMETERS_H
#define PARAMETERS_H

#include "structs.h"

#define SSH_DEFAULT         0 //disabled
#define MEASURE_DEFAULT     1
#define DISCOVER_DEFAULT    10
#define UDP_PORT_DEFAULT    "3382"
#define TELNET_PORT_DEFAULT "3637"
#define TELNET_T_DEFAULT    1

extern int ssh_enabled;
extern int measure_t;
extern int discover_t;
extern char *udp_port;
extern char *telnet_port;
extern int telnet_t;

extern client *all_clients;

void read_parameters(int argc, char **argv);

#endif