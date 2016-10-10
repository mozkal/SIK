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
#include "measure_delays.h"
#include "telnet.h"
#include "server_udp.h"

#define PTR             12
#define A               1
#define INTERNET        1
#define HEADER_SIZE     12
#define PORT_MDNS       5353
#define BUF_SIZE        1024
#define BROADCAST_IP    "224.0.0.251"
#define BUFFER_SIZE         1000
#define MAX_HOSTS           100

extern int ssh_enabled;
extern int measure_t;
extern int discover_t;
extern char *udp_port;
extern char *telnet_port;
extern int telnet_t;

char my_ip[5]; //adres do wysyłania char = ASCII(int)
char hostname[] = "\7cccomp#\0";
char opoznienie_query_msg[] = "\x0b_opoznienia\4_udp\5local";
char tcp_query_msg[] = "\4_ssh\4_tcp\5local";
char A_queries_send[MAX_HOSTS][100];
int A_queries_send_size = 0;
client *all_clients = NULL;

int end_of_message(char *buf) {
    int start = HEADER_SIZE;
    while (buf[start] != 0)
        ++start;
    return start;
}

int create_query(char *package, char *msg, int msg_size, int qtype) {
    DNS_HEADER *dns = NULL;

    memset(package, 0, sizeof(DNS_HEADER));
    dns = (DNS_HEADER *) package;
    dns->q_count = htons(1);

    strncpy(package + HEADER_SIZE, msg, msg_size);
    char * ending = package + HEADER_SIZE + msg_size;

    ending[0] = 0;
    ending[1] = qtype;
    ending[2] = 0;
    ending[3] = 1;
    return 4 + HEADER_SIZE + msg_size;
}

int create_response(char *package, char *msg, int msg_size, int qtype, char *hostnam) {
    DNS_HEADER *dns = NULL;

    memset(package, 0, sizeof(DNS_HEADER));
    dns = (DNS_HEADER *) package;
    dns->qr = 1;
    dns->aa = 1;
    dns->ans_count = htons(1);

    strncpy(package + HEADER_SIZE, msg, msg_size);
    char * ending_char = package + HEADER_SIZE + msg_size;
    *ending_char = 0;
    char * type = ending_char + 1;
    *type = 0;
    *(type + 1) = qtype;
    char * p_class = type + 2;
    if (qtype == PTR) {
        *p_class = 0;
    } else {
        *p_class = 0x80;
    }
    *(p_class + 1) = INTERNET;
    char * TTL = p_class + 2;
    *TTL = 0;
    *(TTL + 1) = 0;
    *(TTL + 2) = 0;
    *(TTL + 3) = 20;
    char * data_length = TTL + 4;
    *data_length = 0;
    if (qtype == PTR) {
        *(data_length + 1) = strlen(hostnam) + 1;
    } else {
        *(data_length + 1) = strlen(hostnam);
    }

    char * response = data_length + 2;
    strncpy(response, hostnam, strlen(hostnam) + 1);
    int size = response - package + strlen(hostnam) + 1;
    return size;
}

void send_broadcast(char *buff, int size) {
    int sock;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;
    struct sockaddr_in server_address;
    int sflags;
    size_t len;
    ssize_t snd_len;
    struct sockaddr_in my_address;
    socklen_t rcva_len;
    int opt_val = 1;

    // 'converting' host/port in string to struct addrinfo
    (void) memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET; // IPv4
    addr_hints.ai_socktype = SOCK_DGRAM;
    addr_hints.ai_protocol = IPPROTO_UDP;
    addr_hints.ai_flags = 0;
    addr_hints.ai_addrlen = 0;
    addr_hints.ai_addr = NULL;
    addr_hints.ai_canonname = NULL;
    addr_hints.ai_next = NULL;
    if (getaddrinfo(BROADCAST_IP, NULL, &addr_hints, &addr_result) != 0) {
        syserr("getaddrinfo4");
    }

    my_address.sin_family = AF_INET;
    my_address.sin_addr.s_addr =
        ((struct sockaddr_in*) (addr_result->ai_addr))->sin_addr.s_addr;
    my_address.sin_port = htons(PORT_MDNS);

    freeaddrinfo(addr_result);
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        syserr("socket");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val)) < 0) {
        perror("SO_REUSEADDR");
    }
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT_MDNS);

    if(bind(sock, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address)) < 0)
        syserr("bind");

    len = size;
    sflags = 0;
    rcva_len = (socklen_t) sizeof(my_address);
    snd_len = sendto(sock, buff, len, sflags,
                     (struct sockaddr *) &my_address, rcva_len);
    if (snd_len != (ssize_t) len) {
        syserr("Broadcast send");
    }

    if (close(sock) == -1)
        syserr("close");
}

void discover_opoznienie() {
    char query[] = "\x0b_opoznienia\4_udp\5local\0";
    char message[100];
    memcpy(message, query, strlen(query) + 1);
    char buffer[BUF_SIZE];
    int size = create_query(buffer, message, strlen(query) + 1, PTR);
    send_broadcast(buffer, size);
}

void discover_tcp() {
    char query[] = "\4_ssh\4_tcp\5local\0";
    char message[100];
    memcpy(message, query, strlen(query) + 1);
    char buffer[BUF_SIZE];
    int size = create_query(buffer, message, strlen(query) + 1, PTR);
    send_broadcast(buffer, size);
}

void* start_discovering(void *args) {
    while(1) {
        discover_opoznienie();
        discover_tcp();
        sleep(discover_t);
    }
}

void send_PTR_response(char *package, char *query, int query_size) {
    char msg[100];
    int msg_size;
    int begin_msg = HEADER_SIZE;
    int end_msg = end_of_message(package);
    strncpy(msg, package + begin_msg, end_msg - begin_msg);
    msg_size = end_msg - begin_msg;
    //strncpy(msg + msg_size, hostname, strlen(hostname));

    char buffer[BUF_SIZE];
    char *ending = malloc(strlen(hostname) + query_size + 1);
    sprintf(ending, "%s", hostname);
    sprintf(ending + strlen(hostname),"%s", query);
    int size = create_response(buffer, msg, msg_size, PTR, ending);
    send_broadcast(buffer, size);
}

int equals(char * first, char * second) {
    if (strncmp(first, second, strlen(second)) == 0)
        return 1;
    else
        return 0;
}

int was_send(char *query) {
    int i;
    for(i = 0; i < A_queries_send_size; ++i) {
        if(equals(query, A_queries_send[i])) {
            return 1;
        }
    }
    return 0;
}

void update_A_query_list(char *query) {
    if (!was_send(query)) {
        memset(A_queries_send[A_queries_send_size], 0, 100);
        strncpy(A_queries_send[A_queries_send_size], query, strlen(query));
        ++A_queries_send_size;
    }
}

void send_A_query(char *ptr_query_package, char *query, int query_size,
                  char *response, int response_size) {
    char *msg;
    int msg_size = response_size;
    msg = malloc(msg_size);
    memset(msg, 0, msg_size);
    strncpy(msg, response, response_size);
    update_A_query_list(msg);

    char buffer[BUF_SIZE];
    int size = create_query(buffer, msg, msg_size, A);
    send_broadcast(buffer, size);
    free(msg);
}

int has_ssh(char *query, int query_size) {
    int i;
    for (i = 0; i < query_size - 5; ++ i) {
        if (query[i] == 's' &&
                query[i + 1] == 's' &&
                query[i + 2] == 'h' )
            return 1;
    }
    return 0;
}


void update_hosts(char *query, int query_size, char *response, int response_size) {
    int ip[4], i;
    char new_ip[30];

    for (i = 0; i < 4; ++i) {
        ip[i] = (response[i] + 256) % 256;
    }
    sprintf(new_ip, "%d.%d.%d.%d%c",  ip[0], ip[1], ip[2], ip[3], '\0');

    client *cl = all_clients;
    while (cl != NULL) {
        if(strncmp(cl->address, new_ip, strlen(new_ip)) == 0)
            break;
        cl = cl->next;
    }
    if (cl == NULL) {
        cl = malloc(sizeof(client));
        cl->next = NULL;
        int len = strlen(new_ip) + 1;
        cl->address = malloc(len);
        strncpy(cl->address, new_ip, strlen(new_ip));
        cl->has_udp = 1;
        cl->has_ssh = 0;

        if(all_clients == NULL)
            all_clients = cl;
        else {
            client *prev =  all_clients;
            client *curr = prev->next;

            while(curr != NULL) {
                prev = curr;
                curr = curr->next;
            }
            prev->next = cl;
        }

        printf("New host: %s\n", cl->address);
        printf("IP: %d %d %d %d\n",  ip[0], ip[1], ip[2], ip[3] );
    }
    if (has_ssh(query, query_size)) {
        cl->has_ssh = 1;
    }
}

int me_asking(char *query) {
    if (strncmp(query, hostname, strlen(hostname)) != 0) {
        return 0;
    }
    //asked for _opoznienia.udp
    if(strncmp(query + strlen(hostname), opoznienie_query_msg, strlen(opoznienie_query_msg)) == 0) {
        return 1;
    //asked for _ssh.tcp
    } else if(strncmp(query + strlen(hostname), tcp_query_msg, strlen(tcp_query_msg)) == 0) {
        return 1;
    }
    return 0;
}

void handle_A_query(char * package, char *query, int query_size) {
    if(me_asking(query)) {
        char buffer[BUF_SIZE];
        int size = create_response(buffer, query, query_size, A, my_ip);
        send_broadcast(buffer, size);
    }
}

int can_response(char *package) {
    char *query = package + HEADER_SIZE;
    int query_size = 0;
    while(query[query_size] != '\0')
        ++query_size;

    if(strncmp(opoznienie_query_msg, query, query_size) == 0)
        return 1;
    if(strncmp(tcp_query_msg, query, query_size) == 0 && ssh_enabled)
        return 1;

    return 0;
}

void handle_data(char *package) {
    char * begin_qname = package + HEADER_SIZE;
    int i = 0;
    while (*(begin_qname + i) != '\0')
        ++i;
    char *qtype = begin_qname + i + 2;
    char *query = package + HEADER_SIZE;
    int query_size = 0;
    while(query[query_size] != '\0')
        ++query_size;
    //QR bit is set
    if((package[2] & (1 << 7)) == 128 ) {
        char *response = qtype + 9;
        int response_size = *(qtype + 8);
        if (*qtype == PTR) {
            send_A_query(package, query, query_size, response, response_size);
        } else if (*qtype == A) {
            update_hosts(begin_qname, i, response, *(qtype + 8));
        } else {
            printf("UNKNOWN TYPE OF PACKAGE: %d\n", *qtype);
        }
    } else {
        if(*qtype == PTR) {
            if(can_response(package))
                send_PTR_response(package, query, query_size);
        } else if (*qtype == A) {
            handle_A_query(package, query, query_size);
        } else {
            printf("UNKNOWN TYPE OF PACKAGE TYPE: %d\n", *qtype);
        }
    }
}

void* mdns_server(void *arg) {
    int sock;
    int flags;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    int i;
    char buffer[BUFFER_SIZE];
    socklen_t rcva_len;
    ssize_t len;
    int opt_val = 1;
    i = 0;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        syserr("socket");
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val)) < 0) {
        perror("SO_REUSEADDR");
    }
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT_MDNS);


    if (bind(sock, (struct sockaddr *) &server_address,
             (socklen_t) sizeof(server_address)) < 0)
        syserr("bind");

    for(;;) {
        do {
            i = i + 1;
            rcva_len = (socklen_t) sizeof(client_address);
            flags = 0;
            len = recvfrom(sock, buffer, sizeof(buffer), flags,
                           (struct sockaddr *) &client_address, &rcva_len);
            if (len < 0)
                syserr("error on datagram from client socket");
            else
                handle_data(buffer);
        } while (len > 0);
    }
}

void set_ip() {
    int s, i;
    struct ifreq ifr;
    char my_address[30];

    s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , "eth0" , IFNAMSIZ - 1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);
    sprintf(my_address, "%s ", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    printf("IP: %s\n", my_address);

    const char * start;
    start = my_address;
    for (i = 0; i < 4; i++) {
        char c;
        int n = 0;
        while(1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
        }
        my_ip[i] = n;
    }
    my_ip[4] = '\0';
}

void start_mdns() {
    pthread_t mdns_t, start_t;
    int rc = pthread_create(&mdns_t, 0, &mdns_server, NULL);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
    rc = pthread_detach(mdns_t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };
    rc = pthread_create(&start_t, 0, &start_discovering, NULL);
    if (rc == -1) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    };
    rc = pthread_detach(start_t);
    if (rc == -1) {
      perror("pthread_detach");
      exit(EXIT_FAILURE);
    };
}

void init_hostname() {
    int seed;
    seed = time(NULL);
    srand(seed);
    hostname[7] =  'A' + rand() % 26;
}

int main(int argc, char **argv) {
    init_hostname();
    set_ip();
    read_parameters(argc, argv);
    start_server();
    start_mdns();
    start_measuring();
    run_telnet();

    return 0;
}
