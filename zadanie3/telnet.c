#include "telnet.h"
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

#include "structs.h"
#include "err.h"
#include "parameters.h"

#define TERMINAL_SIZE       80
#define LINE_SIZE           100

void *read_qa (void *args) {
    int s = ((qa_args *) args)->sock;
    int *scroll = ((qa_args *) args)->scroll;
    free(args);
    int ret;
    char line[LINE_SIZE + 1];
    for(;;) {
        ret = read(s, line, LINE_SIZE);
        if(ret < 0)
            syserr("read");
        if(line[0] == 'q')
            --(*scroll);
        if(line[0] == 'a')
            ++(*scroll);
    }
}

void draw_table(int s, int *scroll) {
    int i, snd_len, msg_size;
    int blanks_cnt;
    uint64_t avg_udp = 0, avg_tcp = 0, avg_icmp = 0;
    char *blanks;
    char *message;
    client *cl = all_clients;

    if(*scroll < 0)
        *scroll = 0;
    int scroll_cnt = 0;
    int count = 0;
    while(cl != NULL) {
        cl = cl->next;
        ++count;
    }
    cl = all_clients;
    while(cl != NULL && scroll_cnt < *scroll) {
        if(count - scroll_cnt <= 3)
            break;
        cl = cl->next;
        ++scroll_cnt;
    }
    *scroll = scroll_cnt;

    int j = 0;
    while(cl != NULL && j < 3) {
        avg_udp = 0, avg_tcp = 0, avg_icmp = 0;
        for(i = 0; i < PROBING; i++) {
            avg_udp += (cl->udp_delay)[i];
            avg_tcp += (cl->tcp_delay)[i];
            avg_icmp += (cl->icmp_delay)[i];
        }
        avg_udp /= 10;
        avg_tcp /= 10;
        avg_icmp /= 10;
        blanks_cnt =(int) (avg_udp + avg_tcp + avg_icmp) / 30;
        if(blanks_cnt > TERMINAL_SIZE - 20)
            blanks_cnt = TERMINAL_SIZE - 20;
        if(blanks_cnt == 0)
            ++blanks_cnt;
        blanks = malloc(blanks_cnt + 1);
        for(i = 0; i < blanks_cnt; i++)
            blanks[i] = ' ';
        blanks[blanks_cnt] = '\0';
        message = malloc(LINE_SIZE);
        memset(message, 0, LINE_SIZE);
        msg_size = sprintf(message, "%s%s%"PRIu64" %"PRIu64" %"PRIu64"\n\r", cl->address,
            blanks, avg_udp, avg_tcp, avg_icmp);

        snd_len = write(s, message, msg_size);
        if(snd_len != msg_size)
            syserr("write telnet");

        free(blanks);
        free(message);
        cl = cl->next;
        ++j;
    };
}

void *handle_telnet (void *args) {
    int ret, s;
    int *scroll;
    socklen_t len;
    char line[LINE_SIZE + 1], peername[LINE_SIZE + 1], peeraddr[LINE_SIZE + 1];
    struct sockaddr_in addr;

    s = *((int *) args);
    free(args);

    //options negotiations
    memset(line, 0, LINE_SIZE);
    //IAC WONT MODE IAC WILL ECHO
    ret = write(s, "\377\375\042\377\373\001", 6); //check
    if (ret == -1) {
      perror("write");
      return 0;
    };
    ret = read(s, line, LINE_SIZE);
    if (ret == -1) {
      perror("read");
      return 0;
    }

    scroll = malloc(sizeof(int));
    *scroll = 0;
    qa_args *args_qa = malloc(sizeof(qa_args));
    args_qa->sock = s;
    args_qa->scroll = scroll;
    pthread_t t;
    int rc = pthread_create(&t, 0, read_qa, args_qa);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
    rc = pthread_detach(t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };
    len = sizeof(addr);
    /* Któż to do nas dzwoni (adres)?  */
    ret = getpeername(s, (struct sockaddr *)&addr, &len);
    if (ret == -1) {
    perror("getsockname");
    exit(1);
    }
    inet_ntop(AF_INET, &addr.sin_addr, peeraddr, LINE_SIZE);
    snprintf(peername, LINE_SIZE, "%s:%d", peeraddr, ntohs(addr.sin_port));

    for (;;) {
        write(s, "\015\033\133\062\112", 5);
        draw_table(s, scroll);
        sleep(telnet_t);
    }
    free(scroll);
    close(s);
}

void run_telnet() {
    int ear;
    socklen_t len;
    struct sockaddr_in server;

    /* Tworzymy gniazdko */
    ear = socket(PF_INET, SOCK_STREAM, 0);
    if (ear == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
    }

    /* Podłączamy do centrali */
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(atoi(telnet_port));
    int rc = bind(ear, (struct sockaddr *)&server, sizeof(server));
    if (rc == -1) {
    perror("bind");
    exit(1);
    }

    /* Każdy chce wiedzieć jaki to port */
    len = (socklen_t)sizeof(server);
    rc = getsockname(ear, (struct sockaddr *)&server, &len);
    if (rc == -1) {
    perror("getsockname");
    exit(EXIT_FAILURE);
    }

    printf("Listening at port %d\n", (int)ntohs(server.sin_port));

    rc = listen(ear, 5);
    if (rc == -1) {
    perror("listen");
    exit(EXIT_FAILURE);
    }

    for (;;) {
        int msgsock;
        int *con;
        pthread_t t;

        msgsock = accept(ear, (struct sockaddr *)NULL, NULL);
        if (msgsock == -1) {
          perror("accept");
          exit(EXIT_FAILURE);
        }

        con = malloc(sizeof(int));
        if (!con) {
          perror("malloc");
          exit(EXIT_FAILURE);
        }
        *con = msgsock;

        rc = pthread_create(&t, 0, handle_telnet, con);
        if (rc == -1) {
          perror("pthread_create");
          exit(EXIT_FAILURE);
        }
        rc = pthread_detach(t);
        if (rc == -1) {
          perror("pthread_detach");
          exit(EXIT_FAILURE);
        }
    }
}
