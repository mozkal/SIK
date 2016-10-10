#include "parameters.h"
#include "measure_delays.h"
#include "err.h"

#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define PROBING             10
#define MILLION             1000000
#define ICMP_HEADER_LEN     8
#define INDEX_BCD           "001101000111000110000100" //347184
#define GROUP_BCD           "00000110" //05
#define BSIZE               1000
#define PORT_SSH            "22"

extern int ssh_enabled;
extern int measure_t;
extern int discover_t;
extern char *udp_port;
extern char *telnet_port;
extern int telnet_t;
int seq = 0;

uint64_t get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * MILLION + tv.tv_usec;
}

void init_udp(struct addrinfo *addr_hints, struct sockaddr_in *my_address,
              struct addrinfo **addr_result, char *host, char *port) {
    memset(addr_hints, 0, sizeof(struct addrinfo));

    addr_hints->ai_family = AF_INET;
    addr_hints->ai_socktype = SOCK_DGRAM;
    addr_hints->ai_protocol = IPPROTO_UDP;
    addr_hints->ai_flags = 0;
    addr_hints->ai_addrlen = 0;
    addr_hints->ai_addr = NULL;
    addr_hints->ai_canonname = NULL;
    addr_hints->ai_next = NULL;
    if(getaddrinfo(host, NULL, addr_hints, addr_result) != 0) {
        syserr("getaddrinfo1");
    }

    my_address->sin_family = AF_INET;
    my_address->sin_addr.s_addr = ((struct sockaddr_in*) ((*addr_result)->ai_addr))->sin_addr.s_addr;
    my_address->sin_port = htons((uint16_t) atoi(port));
}


void compute_udp(client *host) {
    int sock, flags = 0, sflags = 0;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    struct udp_message *buffer;
    size_t len;
    ssize_t snd_len, rcv_len;
    struct sockaddr_in my_address, srvr_address;
    socklen_t rcva_len;
    uint64_t time1, time2;
    init_udp(&addr_hints, &my_address, &addr_result, host->address, udp_port);
    freeaddrinfo(addr_result);

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
        syserr("socket");

    buffer = malloc(MESSAGE_SIZE);
    len = sizeof(time1);
    rcva_len = (socklen_t) sizeof(my_address);

    time1 = get_time(); //time stamp
    snd_len = sendto(sock, &time1, len, sflags,
                     (struct sockaddr *) &my_address, rcva_len);
    if(snd_len != (ssize_t) len) {
        syserr("partial / failed write");
    }
    rcva_len = (socklen_t) sizeof(srvr_address);
    rcv_len = recvfrom(sock, buffer, MESSAGE_SIZE, flags,
                       (struct sockaddr *) &srvr_address, &rcva_len);
    time2 = get_time(); //time stamp
    if(rcv_len < 0) {
        syserr("read");
    }
    if(close(sock) == -1) {
        syserr("close");
    };
    //free(buffer);
    //zaznaczamy opoznienie
    int count = host->udp_count;
    host->udp_delay[count] = time2 - time1;
    count++;
    if(count >= PROBING)
        count -= PROBING;
    host->udp_count = count;
}

unsigned short in_cksum(unsigned short *addr, int len) {
    int             nleft = len;
    int             sum = 0;
    unsigned short  *w = addr;
    unsigned short  answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

        /* 4mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w ;
        sum += answer;
    }

        /* 4add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}

void init_tcp(struct addrinfo *addr_hints, struct addrinfo **addr_result,
              char *host, char *port) {// int port
    int err;

    memset(addr_hints, 0, sizeof(struct addrinfo));
    addr_hints->ai_family = AF_INET;
    addr_hints->ai_socktype = SOCK_STREAM;
    addr_hints->ai_protocol = IPPROTO_TCP;
    err = getaddrinfo(host, port, addr_hints, addr_result);
    if(err != 0)
        syserr("getaddrinfo2: %s\n", gai_strerror(err));
}

void compute_tcp(client *host) {
    int sock, rc;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    uint64_t time1, time2;

    init_tcp(&addr_hints, &addr_result, host->address, PORT_SSH);
    sock = socket(addr_result->ai_family, addr_result->ai_socktype,
                  addr_result->ai_protocol);
    if(sock < 0)
        syserr("socket");

    time1 = get_time(); // time stamp
    if((rc = connect(sock, addr_result->ai_addr, addr_result->ai_addrlen)) < 0) {
        syserr("connect");
    }
    time2 = get_time(); // time stamp

    freeaddrinfo(addr_result);
    if(close(sock) == -1) {
        syserr("close");
    };

    //zaznaczamy opoznienie
    int count = host->tcp_count;
    host->tcp_delay[count] = time2 - time1;
    count++;
    if(count >= PROBING)
        count -= PROBING;
    host->tcp_count = count;
}

void send_packet(int sock, char* s_send_addr) {
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    struct sockaddr_in send_addr;

    struct icmp* icmp;

    char send_buffer[BSIZE];

    int err = 0;
    ssize_t data_len = 0;
    ssize_t icmp_len = 0;
    ssize_t len = 0;

    // 'converting' host/port in string to struct addrinfo
    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_RAW;
    addr_hints.ai_protocol = IPPROTO_ICMP;
    err = getaddrinfo(s_send_addr, 0, &addr_hints, &addr_result);
    if (err != 0)
    syserr("getaddrinfo3: %s\n", gai_strerror(err));

    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr =
      ((struct sockaddr_in*) (addr_result->ai_addr))->sin_addr.s_addr;
    send_addr.sin_port = htons(0);
    freeaddrinfo(addr_result);

    memset(send_buffer, 0, sizeof(send_buffer));
    // initializing ICMP header
    icmp = (struct icmp *) send_buffer;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = htons(0x13);
    icmp->icmp_seq = htons(seq++ % 15000); // sequential number
    char *message = malloc(sizeof(INDEX_BCD) + sizeof(GROUP_BCD) + 1);
    sprintf(message, "%s%s", INDEX_BCD, GROUP_BCD);
    data_len = snprintf(((char*) send_buffer+ICMP_HEADER_LEN),
                      sizeof(send_buffer)-ICMP_HEADER_LEN, "%s", message);
    //free(message);
    if (data_len < 1)
        syserr("snprinf");
    icmp_len = data_len + ICMP_HEADER_LEN; // packet is filled with 0
    icmp->icmp_cksum = 0; // checksum computed over whole ICMP package
    icmp->icmp_cksum = in_cksum((unsigned short*) icmp, icmp_len);

    len = sendto(sock, (void*) icmp, icmp_len, 0, (struct sockaddr *) &send_addr,
               (socklen_t) sizeof(send_addr));
    if(icmp_len != (ssize_t) len)
    syserr("partial / failed write");

    printf("wrote %zd bytes\n", len);
}

void compute_icmp(client *host) {
    int sock;
    uint64_t time1, time2;
    struct sockaddr_in rcv_addr;
    socklen_t rcv_addr_len;

    char rcv_buffer[BSIZE];

    ssize_t len;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
        syserr("socket");

    memset(rcv_buffer, 0, sizeof(rcv_buffer));
    rcv_addr_len = (socklen_t) sizeof(rcv_addr);


    send_packet(sock, host->address);
    time1 = get_time();
    len = recvfrom(sock, (void*) rcv_buffer, sizeof(rcv_buffer), 0,
                 (struct sockaddr *) &rcv_addr, &rcv_addr_len);
    time2 = get_time();
    printf("received %zd bytes from %s\n", len, inet_ntoa(rcv_addr.sin_addr));

    //zaznaczamy opoznienie
    int count = host->icmp_count;
    host->icmp_delay[count] = time2 - time1;
    count++;
    if(count >= PROBING)
        count -= PROBING;
    host->icmp_count = count;
}

void *measure_udp(void *args) {
    client *cl_args;

    client *cl;
    for(;;) {
        cl = all_clients;
        while(cl != NULL) {
            if(cl->has_udp) {
                cl_args = cl;
                compute_udp(cl_args);
            };
            cl = cl->next;
        };
        sleep(measure_t);
    };

    return 0;
}

void *measure_tcp(void *args) {
    client *cl_args;

    client *cl;
    for(;;) {
        cl = all_clients;
        while(cl != NULL) {
            if(cl->has_ssh) {
                cl_args = cl;
                compute_tcp(cl_args);
            };
            cl = cl->next;
        };
        sleep(measure_t);
    };

    return 0;
}

void *measure_icmp(void *args) {
    client *cl;
    client *cl_args;

    for(;;) {
        cl = all_clients;
        while(cl != NULL) {
            if(cl->has_udp) {
                cl_args = cl;
                compute_icmp(cl_args);
            };
            cl = cl->next;
        };
        sleep(measure_t);
    };

    return 0;
}

void start_measuring() {
    pthread_t udp_t, tcp_t, icmp_t;
    int rc = pthread_create(&udp_t, 0, measure_udp, NULL);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
    rc = pthread_detach(udp_t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };
    rc = pthread_create(&tcp_t, 0, measure_tcp, NULL);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
    rc = pthread_detach(tcp_t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };
    rc = pthread_create(&icmp_t, 0, measure_icmp, NULL);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
    rc = pthread_detach(icmp_t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };

}
