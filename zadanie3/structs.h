#ifndef STRUCTS_H
#define STRUCTS_H

#include <inttypes.h>

#define PROBING             10
#define MESSAGE_SIZE        16

typedef struct client {
    char *name;
    char *address;
    int has_udp;
    int has_ssh;
    uint64_t udp_delay[PROBING];
    unsigned int udp_count; //mod 10, bo zastępujemy stare pomiary
    uint64_t tcp_delay[PROBING];
    unsigned int tcp_count; //mod 10
    uint64_t icmp_delay[PROBING];
    unsigned int icmp_count; //mod 10
    struct client *next;
} client;

typedef struct {
    uint64_t time_client;
    uint64_t time_server;
} udp_message;

typedef struct {
    int interval;
    char *port;
} measure_args;

typedef struct {
    int sock;
    int interval;
} telnet_args;

typedef struct {
    int sock;
    int *scroll;
} qa_args;

//DNS header structure
typedef struct
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} DNS_HEADER;

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

#endif