//
// Created by keane on 2020/9/10.
//

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

//Server control functions
void serve_forever(const char *PORT);
// Client request
char    *method,    // "GET" or "POST"
*uri,       // "/index.html" things before '?'
*qs,        // "a=1&b=2"     things after  '?'
*prot;      // "HTTP/1.1"
char    *payload;     // for POST
int      payload_size;
char *request_header(const char* name);
// user shall implement this function
void route();
// some interesting macro for `route()`
#define ROUTE_START()       if (0) {
#define ROUTE(METHOD,URI)   } else if (strcmp(URI,uri)==0&&strcmp(METHOD,method)==0) {
#define ROUTE_GET(URI)      ROUTE("GET", URI)
#define ROUTE_POST(URI)     ROUTE("POST", URI)
#define ROUTE_END()         } else printf(\
                                "HTTP/1.1 500 Not Handled\r\n\r\n" \
                                "The server has no handler to the request.\r\n" \
                            );

#define CONNMAX 1000
static int listenfd, clients[CONNMAX];

static void error(char *);

static void startServer(const char *);

static void respond(int);

typedef struct {
    char *name, *value;
} header_t;
static header_t reqhdr[17];
static int clientfd;

static char *buf;

void serve_forever(const char *PORT) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int slot = 0;
    printf("Server started http://127.0.0.1:%s\n", PORT);
    for (int i = 0; i < CONNMAX; i++) {
        clients[i] = -1;
    }
    startServer(PORT);
    // 如果把这个注释掉就正常了
    // signal(SIGCHLD, SIG_IGN);
    // ACCEPT connections
    while (1) {
        addrlen = sizeof(clientaddr);
        clients[slot] = accept(listenfd, (struct sockaddr *) &clientaddr, &addrlen);
        if (clients[slot] < 0) {
            perror("accept() error");
        } else {
            if (fork() == 0) {
                respond(slot);
                exit(0);
            }
        }
        while (clients[slot] != -1) {
            slot = (slot + 1) % CONNMAX;
        }
    }
}
void startServer(const char *port) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        perror("getaddrinfo() error");
        exit(1);
    }
    for (p = res; p != NULL; p = p->ai_next) {
        int option = 1;
        listenfd = socket(p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1) {
            continue;
        }
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
    }
    if (p == NULL) {
        perror("socket() or bind()");
        exit(1);
    }
    freeaddrinfo(res);
    if (listen(listenfd, 1000000) != 0) {
        perror("listen() error");
        exit(1);
    }
}

char *request_header(const char *name) {
    header_t *h = reqhdr;
    while (h->name) {
        if (strcmp(h->name, name) == 0) return h->value;
        h++;
    }
    return NULL;
}

std::string data = "";

void respond(int n) {
    int rcvd;
    buf = (char *) malloc(65535);
    rcvd = recv(clients[n], buf, 65535, 0);
    if (rcvd < 0) {
        fprintf(stderr, ("recv() error\n"));
    }else if (rcvd == 0) {
        fprintf(stderr, "Client disconnected upexpectedly.\n");
    }else{
        buf[rcvd] = '\0';
        method = strtok(buf, " \t\r\n");
        uri = strtok(NULL, " \t");
        prot = strtok(NULL, " \t\r\n");
        fprintf(stderr, "\x1b[32m + [%s] %s\x1b[0m\n", method, uri);
        if (qs = strchr(uri, '?')) {
            *qs++ = '\0'; //split URI
        } else {
            qs = uri - 1; //use an empty string
        }
        header_t *h = reqhdr;
        char *t, *t2;
        bool content = false;
        while (h < reqhdr + 16) {
            char *k, *v, *t;
            if (content) {
                k = strtok(NULL, "\r\n: \t");
                if (!k) break;
                v = strtok(NULL, "\r\n");
                while (*v && *v == ' ') v++;
                data = std::string(k, k + strlen(k));
                data += ": ";
                data += v;
            } else {
                k = strtok(NULL, "\r\n: \t");
                if (!k) break;
                v = strtok(NULL, "\r\n");
                while (*v && *v == ' ') v++;
            }
            h->name = k;
            h->value = v;
            h++;
            fprintf(stderr, "[H] %s: %s\n", k, v);
            t = v + 1 + strlen(v);
            if (t[1] == '\r' && t[2] == '\n') {
                content = true;
            }
        }
        t = strtok(NULL, "\r\n");
        t2 = request_header("Content-Length"); // and the related header if there is
        payload = t;
        payload_size = t2 ? atol(t2) : (rcvd - (t - buf));
        clientfd = clients[n];
        dup2(clientfd, STDOUT_FILENO);
        close(clientfd);
        // call router
        route();
        fflush(stdout);
        shutdown(STDOUT_FILENO, SHUT_WR);
        close(STDOUT_FILENO);
    }
    shutdown(clientfd, SHUT_RDWR);         //All further send and recieve operations are DISABLED...
    close(clientfd);
    clients[n] = -1;
}