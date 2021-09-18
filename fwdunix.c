/* Copyright (C) 2010  Paul Sheer  All rights reserved. */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 Solaris:
    cc -o fwdunix-simplified fwdunix-simplified.c -lsocket
 Linux:
    cc -o fwdunix-simplified fwdunix-simplified.c
*/


#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

static int listen_socket(int listen_port)
{
    struct sockaddr_in a;
    int s;
    int yes = 1;

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof(yes))
        == -1) {
        perror("setsockopt");
        close(s);
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin_port = htons(listen_port);
    a.sin_family = AF_INET;
    if (bind(s, (struct sockaddr *) &a, sizeof(a)) == -1) {
        perror("bind");
        close(s);
        return -1;
    }
    listen(s, 10);
    return s;
}

static int connect_socket(char *address)
{
    struct sockaddr_un a;
    int s;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, address, sizeof(a.sun_path));
    a.sun_path[sizeof(a.sun_path) - 1] = '\0';

    if (connect(s, (struct sockaddr *) &a, sizeof(a)) == -1) {
        perror("connect()");
        shutdown(s, SHUT_RDWR);
        close(s);
        return -1;
    }
    return s;
}


#define ISDIG(c)        ((c) >= '0' && (c) <= '9')

#define NUM(i)                                  \
            i = (*p++ - '0');                   \
            if (ISDIG(*p)) {                    \
                i *= 10;                        \
                i += (*p++ - '0');              \
                if (ISDIG(*p))                  \
                {                               \
                    i *= 10;                    \
                    i += (*p++ - '0');          \
                    if (i > 255)                \
                        return 1;               \
                }                               \
            }

static int iprange_scan(const char *_p, const unsigned char *_address,
                        int *found)
{
    unsigned int address;
    const unsigned char *p;
    p = (const unsigned char *) _p;
    address = _address[0];
    address <<= 8;
    address |= _address[1];
    address <<= 8;
    address |= _address[2];
    address <<= 8;
    address |= _address[3];
    if (found)
        *found = 0;
    for (;;) {
        unsigned int net = 0, i, mask;
        if (!*p)
            return 0;
        if (!ISDIG(*p)) {
            p++;
            continue;
        }
        NUM(i);
        net |= i;
        if (*p++ != '.')
            return 1;
        NUM(i);
        net <<= 8;
        net |= i;
        if (*p++ != '.')
            return 1;
        NUM(i);
        net <<= 8;
        net |= i;
        if (*p++ != '.')
            return 1;
        NUM(i);
        net <<= 8;
        net |= i;
        if (*p == '/') {
            p++;
            NUM(i);
            if (*p == '.') {
                p++;
                mask = i;
                NUM(i);
                mask <<= 8;
                mask |= i;
                if (*p++ != '.')
                    return 1;
                NUM(i);
                mask <<= 8;
                mask |= i;
                if (*p++ != '.')
                    return 1;
                NUM(i);
                mask <<= 8;
                mask |= i;
            } else {
                mask = 0xffffffff;
                if (i > 32)
                    return 1;
                mask <<= (32 - i);
            }
        } else {
            mask = 0xffffffff;
        }
        if (found && (address & mask) == (net & mask)) {
            *found = 1;
            return 0;
        }
        if (ISDIG(*p))
            return 1;
    }
    return 0;
}

#define SHUT_FD(fd)     do {                                    \
                            if ((fd) != -1) {                   \
                                shutdown((fd), SHUT_RDWR);      \
                                close(fd);                      \
                                (fd) = -1;                      \
                            }                                   \
                        } while (0)


/* a little more than two TCP packets: */
#define BUF_SIZE        3072

struct fd_object {
    struct fd_object *next;
    int fd1, fd2;
    char buf1[BUF_SIZE], buf2[BUF_SIZE];
    int buf1_avail, buf1_written;
    int buf2_avail, buf2_written;
};

int term_app = 0;

int main(int argc, char *argv[])
{
    int h, found_ip = 0;
    struct fd_object *list = NULL, *o;

    if (argc != 4
        || iprange_scan(argv[3], (const unsigned char *) &found_ip,
                        &found_ip)) {
        fprintf(stderr,
                "Usage\n\tfwd <listen-port> <unix-socket> <allowed-ips>\n"
                "\tfwd 6000 /tmp/.X11-unix/X0 192.168.2.0/24,10.0.0.0/8\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGPIPE, SIG_IGN);
#ifdef SIGTTOU
    signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
    signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGHUP
    signal(SIGHUP, SIG_IGN);
#endif
#ifdef SIGSTOP
    signal(SIGSTOP, SIG_IGN);
#endif

    h = listen_socket(atoi(argv[1]));
    if (h == -1)
        exit(EXIT_FAILURE);

    while (!term_app) {
        int r, nfds = 0;
        fd_set rd, wr;

        FD_ZERO(&rd);
        FD_ZERO(&wr);
        FD_SET(h, &rd);
        nfds = max(nfds, h);

        o = (struct fd_object *) &list;
        while (o->next) {
            if (o->next->fd1 == -1 && o->next->fd2 == -1) {
                struct fd_object *f;
                f = o->next;
                o->next = o->next->next;
                free(f);
            } else {
                o = o->next;
            }
        }

#define SETUP(fd, set, count)                                   \
            if (o->fd != -1 && (count) > 0) {                   \
                FD_SET(o->fd, &set);                            \
                nfds = max(nfds, o->fd);                        \
            }

        for (o = list; o; o = o->next) {
            SETUP(fd1, rd, BUF_SIZE - o->buf1_avail);
            SETUP(fd2, rd, BUF_SIZE - o->buf2_avail);
            SETUP(fd1, wr, o->buf2_avail - o->buf2_written);
            SETUP(fd2, wr, o->buf1_avail - o->buf1_written);
        }

        r = select(nfds + 1, &rd, &wr, NULL, NULL);

        if (r == -1 && errno == EINTR)
            continue;

        if (r == -1) {
            perror("select()");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(h, &rd)) {
            unsigned int l;
            struct sockaddr_in client_address;

            memset(&client_address, 0, l = sizeof(client_address));
            r = accept(h, (struct sockaddr *) &client_address, &l);
            if (r != -1) {
                found_ip = 0;
                iprange_scan(argv[3], (const unsigned char *)
                             &client_address.sin_addr.s_addr, &found_ip);
                if (found_ip) {
                    o = malloc(sizeof(*o));
                    o->buf1_avail = o->buf1_written = 0;
                    o->buf2_avail = o->buf2_written = 0;
                    o->fd1 = r;
                    o->fd2 = connect_socket(argv[2]);
                    if (o->fd2 == -1) {
                        SHUT_FD(o->fd1);
                        free(o);
                    } else {
                        int yes = 1;
                        setsockopt(o->fd1, IPPROTO_TCP, TCP_NODELAY,
                                   (char *) &yes, sizeof(yes));
                        setsockopt(o->fd2, IPPROTO_TCP, TCP_NODELAY,
                                   (char *) &yes, sizeof(yes));
                        o->next = list;
                        list = o;
                    }
                } else {
                    SHUT_FD(r);
                }
            }
        }
#define PROCESS(fd, op, set, buf, end, count)                   \
            if (o->fd != -1)                                    \
                if (FD_ISSET(o->fd, &set)) {                    \
                    r = op(o->fd, o->buf + o->end, count);      \
                    if (r < 1)                                  \
                        SHUT_FD(o->fd);                         \
                    else                                        \
                        o->end += r;                            \
                }

        for (o = list; o; o = o->next) {
            PROCESS(fd1, read, rd, buf1, buf1_avail,
                    BUF_SIZE - o->buf1_avail);
            PROCESS(fd2, read, rd, buf2, buf2_avail,
                    BUF_SIZE - o->buf2_avail);
            PROCESS(fd1, write, wr, buf2, buf2_written,
                    o->buf2_avail - o->buf2_written);
            PROCESS(fd2, write, wr, buf1, buf1_written,
                    o->buf1_avail - o->buf1_written);

            /* check if write data has caught read data */
            if (o->buf1_written == o->buf1_avail)
                o->buf1_written = o->buf1_avail = 0;
            if (o->buf2_written == o->buf2_avail)
                o->buf2_written = o->buf2_avail = 0;

            /* one side has closed the connection, keep
             * writing to the other side until empty */
            if (o->fd1 == -1 && o->buf1_avail == o->buf1_written)
                SHUT_FD(o->fd2);
            if (o->fd2 == -1 && o->buf2_avail == o->buf2_written)
                SHUT_FD(o->fd1);
        }
    }
    exit(EXIT_SUCCESS);
}


