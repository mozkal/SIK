#include "server_udp.h"
#include "structs.h"
#include "err.h"
#include "measure_delays.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>

extern char *udp_port;

void *server_udp(void *args) {
    int sock;
    int flags, sflags;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    uint64_t *buffer;
    udp_message *message;
    socklen_t snda_len, rcva_len;
    ssize_t len, snd_len;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
        syserr("socket");

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons((uint16_t) atoi(udp_port));

    if(bind(sock, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address)) < 0)
        syserr("bind");

    snda_len = (socklen_t) sizeof(client_address);

    for(;;) {
        do {
            buffer = malloc(MESSAGE_SIZE);
            memset(buffer, 0, MESSAGE_SIZE);
            rcva_len = (socklen_t) sizeof(client_address);
            flags = 0;
            len = recvfrom(sock, buffer, MESSAGE_SIZE, flags,
                           (struct sockaddr *) &client_address, &rcva_len);
            if(len < 0)
                syserr("error on datagram from client socket");
            else {
                message = malloc(MESSAGE_SIZE);
                message->time_client = *buffer;
                message->time_server = get_time();
                len = sizeof(*message);
                sflags = 0;
                snd_len = sendto(sock, message, len, sflags,
                                (struct sockaddr *) &client_address, snda_len);
                if(snd_len != len)
                    syserr("error on sending datagram to client socket");
            }
            //free(buffer);
        } while(len > 0);
            printf("finished exchange\n");
    }

    if(close(sock) == -1) {
        syserr("close");
    };
}

void start_server() {
    pthread_t server_t;
    int rc = pthread_create(&server_t, 0, &server_udp, NULL);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
    rc = pthread_detach(server_t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };
}