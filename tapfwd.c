/* Copyright (C) 2020  Paul Sheer, All rights reserved. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include <pwd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include "aes.h"
#include "ipv6scan.h"
#include "fastsec.h"
#include "randseries.h"




struct cmdlineoption {
    int co_pubkey;
    const char *co_remote;
    const char *co_pseudoip;
    const char *co_range;
    const char *co_listen;
    const char *co_clientname;
    char co_dev[64];
    int co_port;
    int co_auth;
    int co_noauth;
    int co_nostore;
};

static void cmdlineoption_setdefaults (struct cmdlineoption *o)
{
    memset (o, '\0', sizeof (*o));
    strcpy (o->co_dev, "tun0");
    o->co_port = 27683;
}

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))

static void setup_sig_handlers (void)
{
    signal (SIGHUP, SIG_IGN);
#ifdef SIGPIPE
    signal (SIGPIPE, SIG_IGN);
#endif
#ifdef SIGALRM
    signal (SIGALRM, SIG_IGN);
#endif
#ifdef SIGCHLD
    signal (SIGCHLD, SIG_IGN);
#endif
#ifdef SIGCONT
    signal (SIGCONT, SIG_IGN);
#endif
#ifdef SIGTSTP
    signal (SIGTSTP, SIG_IGN);
#endif
#ifdef SIGTTIN
    signal (SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTTOU
    signal (SIGTTOU, SIG_IGN);
#endif
}

void hexdump (const char *msg, unsigned char *s, int len)
{
    int i;
    printf ("%s: ", msg);
    for (i = 0; i < len; i++)
        printf ("%02x", (unsigned int) s[i]);
    printf ("\n");
}

static void do_system (const char *shell_cmd)
{
    int r;
    r = system (shell_cmd);
    if (r == -1 || !WIFEXITED (r)) {
        fprintf (stderr, "error: %s\n", shell_cmd);
        exit (1);
    }
    if (WEXITSTATUS (r)) {
        fprintf (stderr, "error: returned %d: %s\n", (int) WEXITSTATUS (r), shell_cmd);
        exit (1);
    }
}

static void perror2 (const char *msg1, const char *msg2)
{
    char t[1024];
    if (msg2)
        snprintf (t, sizeof (t), "error: %s: %s", msg1, msg2);
    else
        snprintf (t, sizeof (t), "error: %s", msg1);
    if (errno)
        perror (t);
    else
        fprintf (stderr, "%s\n", t);
}

static void fatalerror2 (const char *msg1, const char *msg2)
{
    perror2 (msg1, msg2);
    exit (1);
}

static void fatalerror (const char *msg)
{
    perror2 (msg, NULL);
    exit (1);
}

static void pperror (const char *msg)
{
    perror2 (msg, NULL);
}

static void become_nobody (void)
{
    struct passwd *pwd;
    int found = 0;
    int line_count = 0;

    setpwent ();
    while ((pwd = getpwent ()) != NULL) {
        if (line_count++ > 1000)
            break;
        if (!strcmp (pwd->pw_name, "nobody")) {
            if (setgid (pwd->pw_gid))
                fatalerror ("setgid to nobody");
            if (setegid (pwd->pw_gid))
                fatalerror ("setegid to nobody");
            if (setuid (pwd->pw_uid))
                fatalerror ("setuid to nobody");
            if (seteuid (pwd->pw_uid))
                fatalerror ("seteuid to nobody");
            found = 1;
            printf ("set credentials to user to 'nobody'\n");
            break;
        }
    }
    endpwent ();

    if (!found) {
        fprintf (stderr, "could not find 'nobody' user\n");
        exit (1);
    }
}

static void str_l_cpy (char *d, const char *s, int n)
{
    for (; n > 1 && *s; n--)
        *d++ = *s++;
    if (n)
        *d = '\0';
}

static int tun_alloc (char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open ("/dev/net/tun", O_RDWR)) < 0)
        return -1;

    memset (&ifr, 0, sizeof (ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN;
    if (*dev)
        str_l_cpy (ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl (fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close (fd);
        return err;
    }
    strcpy (dev, ifr.ifr_name);
    return fd;
}


union sockaddrin4in6 {
    struct sockaddr in;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
};

static int addr2sockaddr (const void *addr, int addrlen, union sockaddrin4in6 *out)
{
    if (addrlen == 4) {
        out->in4.sin_family = AF_INET;
        memcpy (&out->in4.sin_addr, addr, 4);
    } else if (addrlen == 16) {
        out->in6.sin6_family = AF_INET6;
        memcpy (&out->in6.sin6_addr, addr, 16);
    } else {
        return 1;
    }
    return 0;
}

static int sockaddr2addr (union sockaddrin4in6 *in, void **addr, int *addrlen)
{
    if (in->in.sa_family == AF_INET) {
        *addr = &in->in4.sin_addr;
        *addrlen = 4;
    } else if (in->in.sa_family == AF_INET6) {
        *addr = &in->in6.sin6_addr;
        *addrlen = 16;
    } else {
        return 1;
    }
    return 0;
}

static void make_os_sock (const char *msg, int *s, union sockaddrin4in6 *a, const char *address, int port)
{
    char addr[16];
    int addrlen;

    *s = -1;
    memset (a, 0, sizeof (*a));
    if (text_to_ip (address, NULL, addr, &addrlen) || addr2sockaddr (addr, addrlen, a)) {
        fprintf (stderr, "%s: bad address format %s\n", msg, address);
        exit (1);
    }
    a->in4.sin_port = htons (port);
    if ((*s = socket (a->in.sa_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
        fatalerror2 (msg, "socket");
}

static int listen_socket (const char *msg, const char *address, int port)
{
    union sockaddrin4in6 a;
    int s;
    int yes = 1;

    make_os_sock (msg, &s, &a, address, port);

    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof (yes)) == -1)
        fatalerror2 (msg, "setsockopt");
    if (bind (s, &a.in, sizeof (a)) == -1)
        fatalerror2 (msg, "bind");
    listen (s, 10);
    return s;
}

#define SHUTSOCK(sock)  \
        do { \
            shutdown ((sock), 2); \
            close (sock); \
            (sock) = -1; \
        } while(0)

#define errno_TEMP()            (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR || errno == EINPROGRESS)

static int connect_socket (const char *msg, const char *address, int port)
{
    char m[256];
    time_t t1, t2;
    union sockaddrin4in6 a;
    int r;
    int s;

    make_os_sock (msg, &s, &a, address, port);

    fcntl (s, F_SETFL, O_NONBLOCK);

  try_again:
    r = connect (s, (struct sockaddr *) &a, sizeof (a));

    if (r == -1) {
        if (errno == EINTR)
            goto try_again;
        if (errno == EALREADY || errno == EINPROGRESS)
            r = 0;
#ifdef EISCONN
        if (errno == EISCONN)
            r = 0;
#endif
    }

    if (r == -1)
        goto errout;

    time (&t1);

    for (;;) {
        struct timeval tv;
        int sr;
        fd_set wr;
        char c;
        socklen_t l;
        union sockaddrin4in6 a;

        time (&t2);
        if (t2 - t1 > 5) {
            fprintf (stderr, "%s: timeout waiting for response from remote: connect(addr=%s port=%d)\n", msg, address, (int) port);
            SHUTSOCK (s);
            return -1;
        }

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        FD_ZERO (&wr);
        FD_SET (s, &wr);

        sr = select (s + 1, NULL, &wr, NULL, &tv);

        if (sr != 1)
            FD_ZERO (&wr);
        if (sr == -1 && !(errno_TEMP () || errno == ENOTCONN))
            goto errout;
        if (!FD_ISSET (s, &wr)) {
            r = recv (s, &c, 1, 0);
            if (r < 0 && (errno_TEMP () || errno == ENOTCONN)) {
                continue;
            } else if (r <= 0)
                goto errout;
        }
        l = sizeof (a);
        r = getpeername (s, &a.in, &l);
        if (r) {
            if (errno == ENOTCONN || errno == EINVAL) {
                errno = 0;
                recv (s, &c, 1, 0);
            }
            goto errout;
        }
        return s;
    }

  errout:
    snprintf (m, sizeof (m), "%s: connect(addr=%s port=%d)", msg, address, (int) port);
    pperror (m);
    SHUTSOCK (s);
    return -1;
}



static int configure_network (struct cmdlineoption *cmdlineopt)
{
    char ifconfig[128];
    int devfd;

    printf ("loading module... (modprobe tun)\n");
    do_system ("modprobe tun");
    printf ("creating device... (mkdir /dev/net ; mknod /dev/net/tun c 10 200 ; chmod 0666 /dev/net/tun)\n");
    do_system ("mkdir -p /dev/net");
    do_system ("test -c /dev/net/tun || mknod /dev/net/tun c 10 200");
    do_system ("chmod 0600 /dev/net/tun");

    printf ("opening %s...\n", cmdlineopt->co_dev);
    devfd = tun_alloc (cmdlineopt->co_dev);
    if (devfd < 0)
        fatalerror (cmdlineopt->co_dev);

    snprintf (ifconfig, sizeof (ifconfig), "ifconfig %s %s netmask 255.255.255.0 mtu 1344 up", cmdlineopt->co_dev, cmdlineopt->co_pseudoip);
    printf ("configuring network... (%s) \n", ifconfig);
    do_system (ifconfig);
    snprintf (ifconfig, sizeof (ifconfig), "ifconfig %s", cmdlineopt->co_dev);
    printf ("--\n");
    do_system (ifconfig);
    printf ("--\n");

    return devfd;
}



struct cryptobuf {
    int avail;
    int written;
    char data[FASTSEC_BUF_SIZE];
    unsigned char key[FASTSEC_KEY_SZ];
    struct aes_key_st aes;
    uint64_t non_replay_counter;
};


static void make_encrypted_packet (struct cryptobuf *buf, struct randseries *s, int pkttype, int len)
{
    buf->avail += fastsec_encrypt_packet (&buf->data[buf->avail], &buf->non_replay_counter, &buf->aes, s, pkttype, len);
}


static void print_help (void)
{
    printf ("\n");
    printf ("Usage:\n");
    printf ("  tapfwd  -c <remoteaddress> -ip <localprivateaddress> -n <clientname>\n");
    printf ("      [-p <port>] [-tun <dev>] [-auth]\n");
    printf ("  tapfwd  -l <listenaddress> -allow <addr>/<mask>[,<addr>/<mask>]... -ip <localprivateaddress>\n");
    printf ("      [-p <port>] [-tun <dev>] [-noauth] [-nostore]\n");
    printf ("  tapfwd  -pubkey\n");
    printf ("\nOptions:\n");
    printf ("  -l <listenaddress>       Server mode. Listens for incoming connections on <listenaddress>.\n");
    printf ("                           -auth is enabled by default for server mode to prevent non-authorized\n");
    printf ("                           clients from connecting.\n");
    printf ("  -c <remoteaddress>       Client mode. argument is an IP address.\n");
    printf ("  -n <clientname>          An arbitrary user name to identify the client machine to the server.\n");
    printf ("  -ip <localpriv>          VPN local gateway IP address. This address will be private. You will\n");
    printf ("                           need to set up routes to this address.\n");
    printf ("  -allow <addr>/<mask>[,<addr>/<mask>]...\n");
    printf ("                           Restrict incoming connections to clients that match.\n");
    printf ("  -p <port>                Preferred TCP port over which to tunnel traffic. Default 27683\n");
    printf ("  -tun <dev>               Preferred tun device. Default tun0\n");
    printf ("  -auth                    Indicates that a remote must already have its own line within\n");
    printf ("                           tapfwd-ecurve-remote-public-key.dat or else the handshake will\n");
    printf ("                           be rejected. That is, new public keys will not be stored. This\n");
    printf ("                           is the default for server mode.\n");
    printf ("  -noauth                  For server mode, allow clients with new (unknown) public keys to connect.\n");
    printf ("  -nostore                 For server mode, like -noauth but don't store any client public keys.\n");
    printf ("                           This is useful if you think your clients might be resetting their public\n");
    printf ("                           keys and thus are unable to connect.\n");
    printf ("  -pubkey                  Print out the public key for copying to another host.\n");
    printf ("\nExample:\n");
    printf ("  remote@root$> tapfwd -l 0.0.0.0 -allow 123.4.5.0/24 -ip 172.16.1.6 -noauth\n");
    printf ("  local@root$> tapfwd -c 99.1.2.3 -ip 172.16.1.5 -n bill@microsoft.com\n");
    printf ("\nYou can then do something useful like display an X Window System program back through a NATed\n");
    printf ("firewall as follows. (You will need to configure your X Server to accept TCP connections):\n");
    printf ("  remote@root$> DISPLAY=172.16.1.5:0.0 xterm\n");
    printf ("\nTapfwd is a virtual private network (VPN) tool to create an IP tunnel between two machines,\n");
    printf ("with strong security in mind. The protocol of tapfwd involves curve446 and curve25519 elliptic\n");
    printf ("curves for key exchange and AES256 CBC for encryption and authentication. The protocol combines\n");
    printf ("both EC curves to mitigate against a weakness in either one. Public keys of remote hosts are\n");
    printf ("stored on the file-system for future authentication.\n");
    printf ("\nFiles:\n");
    printf ("  /var/tmp/tapfwd-ecurve-private-key.dat           Stores the private key. Keep this secret.\n");
    printf ("  /var/tmp/tapfwd-ecurve-public-key.dat            Stores public key of local host.\n");
    printf ("  /var/tmp/tapfwd-ecurve-remote-public-key.dat     Stores public keys of remote hosts.\n");
    printf ("\nIf the remote changes its public key, or if a 'man-in-the-middle-attack' is attempted,\n");
    printf ("then tapfwd will output an error message,\n");
    printf ("\n    error: /var/tmp/tapfwd-ecurve-remote-public-key.dat:N: public key for remote 'V' does not match\n");
    printf ("\nwhere N is the line number of the expected key and V is <clientname> or <remoteaddress>.\n");
    printf ("\nPerfect security can be obtained by running tapfwd -pubkey on the remote machine and placing\n");
    printf ("the output into a new line in tapfwd-ecurve-remote-public-key.dat on the local machine,\n");
    printf ("and visa-versa. For example the file root@123.4.5.6:/var/tmp/tapfwd-ecurve-remote-public-key.dat\n");
    printf ("contains:\n\n");
    printf ("   99.1.2.3     5c76b317abbb1c2617c53480a96eac9fdee47d01989bcd7fd003714c7dc53f004e\n");
    printf ("\nand the file root@99.1.2.3:/var/tmp/tapfwd-ecurve-remote-public-key.dat contains:\n\n");
    printf ("   bill@microsoft.com     169db5a12a3167b12af96d3fc0f243fd3f22e88ea73bf3a1c69481365ec9340123\n");
    printf ("\nBe sure to use the -auth option.\n");
    printf ("\nNotes:");
    printf ("\n  Root privileges are dropped after startup. IPv6 is supported. Intel AES-NI (hardware AES\n");
    printf ("  encryption) and 128-bit hardware arithmetic is used on 64-bit CPUs. Key exchanges take in the\n");
    printf ("  order of milliseconds. The 32-bit version is software-only and takes approximate 10X longer to\n");
    printf ("  perform a key exchange.\n");
    printf ("\n");
}

static void cmdlineoption_parse (struct cmdlineoption *cmdlineopt, int argc, char **argv)
{
    int i;
#define ARGER   do { \
                    if (i >= argc - 1) { \
                        fprintf (stderr, "error: cmdline: argument expected after %s\n", argv[i]); \
                        exit (1); \
                    } \
                } while(0)

    for (i = 1; i < argc; i++) {
        if (!strcmp (argv[i], "-l")) {
            cmdlineopt->co_listen = argv[++i];
        } else if (!strcmp (argv[i], "-pubkey")) {
            cmdlineopt->co_pubkey = 1;
            break;
        } else if (!strcmp (argv[i], "-h") || !strcmp (argv[i], "-?") || !strcmp (argv[i], "-help") || !strcmp (argv[i], "--help")) {
            print_help ();
            exit (0);
        } else if (!strcmp (argv[i], "-nostore")) {
            cmdlineopt->co_nostore = 1;
        } else if (!strcmp (argv[i], "-auth")) {
            cmdlineopt->co_auth = 1;
        } else if (!strcmp (argv[i], "-noauth")) {
            cmdlineopt->co_noauth = 1;
        } else if (!strcmp (argv[i], "-tun")) {
            ARGER;
            strcpy(cmdlineopt->co_dev, argv[++i]);
        } else if (!strcmp (argv[i], "-ip")) {
            ARGER;
            cmdlineopt->co_pseudoip = argv[++i];
        } else if (!strcmp (argv[i], "-n")) {
            ARGER;
            cmdlineopt->co_clientname = argv[++i];
        } else if (!strcmp (argv[i], "-allow")) {
            ARGER;
            cmdlineopt->co_range = argv[++i];
        } else if (!strcmp (argv[i], "-c")) {
            ARGER;
            cmdlineopt->co_remote = argv[++i];
        } else if (!strcmp (argv[i], "-p")) {
            ARGER;
            cmdlineopt->co_port = atoi (argv[++i]);
        } else {
            fprintf (stderr, "error: cmdline: %s, try  tapfwd -h\n", argv[i]);
            exit (1);
        }
    }
}

void aes_test (void)
{
    const unsigned char *blk = (const unsigned char *) "12345678ABCDEFGHw09tupawoijgagja";
    const unsigned char *key = (const unsigned char *) "qfedfhgwl6bgfgqwelpkjg09834t6rqg";
    unsigned char out[32];
    unsigned char iv[16];
    struct aes_key_st keyc;

    memcpy (iv, "qp4wfffffww0egij", 16);
    aes_ni_set_encrypt_key (key, &keyc);
    aes_ni_cbc_encrypt (blk, out, 32, &keyc, iv);
    hexdump ("out", out, 32);
    hexdump ("iv", iv, 16);
    memcpy (iv, "qp4wfffffww0egij", 16);
    aes_ni_set_decrypt_key (key, &keyc);
    aes_ni_cbc_decrypt (out, out, 32, &keyc, iv);
    printf ("%32s\n", out);
    hexdump ("iv", iv, 16);

    printf ("\n");

    memcpy (iv, "qp4wfffffww0egij", 16);
    aes_set_encrypt_key (key, 256, &keyc);
    aes_cbc128_encrypt (blk, out, 32, &keyc, iv);
    hexdump ("out", out, 32);
    hexdump ("iv", iv, 16);
    memcpy (iv, "qp4wfffffww0egij", 16);
    aes_set_decrypt_key (key, 256, &keyc);
    aes_cbc128_decrypt (out, out, 32, &keyc, iv);
    printf ("%32s\n", out);
    hexdump ("iv", iv, 16);

    exit (0);
}


static long long microtime (void)
{
    struct timeval tv;
    long long r;
    gettimeofday (&tv, NULL);
    r = tv.tv_sec;
    r *= 1000000;
    r += tv.tv_usec;
    return r;
}

unsigned long hash_str (const char *s)
{
    unsigned long c = 0;
    while (*s) {
        c ^= *s++;
        c ^= (((c + 9UL) * (c + 2UL) * 401UL) >> 1);
        c ^= (c << 13);
    }
    return c;
}

int main (int argc, char **argv)
{
    struct fastsec fs_, *fs;
    struct cmdlineoption cmdlineopt_;
    struct cmdlineoption *cmdlineopt;
    time_t last_hb_sent, last_hb_recv;
    int future_packet_sent = 0;
    uint64_t pkt_recv_count;
    int client_close_req_recieved = 0;
    int server_ticket_recieved = 0;
    union reconnect_ticket save_ticket;
    int devfd, sock = -1, h = -1;
    struct iprange_list *iprange = NULL;
    struct randseries *randseries;
    struct cryptobuf buf1, buf2;
    struct fastsec_keyexchange_info fsinfo;
    enum fastsec_result fr;
    char errmsg[256];
    const char *privkey_fname = "/var/tmp/tapfwd-ecurve-private-key.dat";
    const char *remotepubkey_fname = "/var/tmp/tapfwd-ecurve-remote-public-key.dat";
    const char *pubkey_fname = "/var/tmp/tapfwd-ecurve-public-key.dat";

    fastsec_init ();

    randseries = randseries_new (FASTSEC_KEY_SZ);

    cmdlineopt = &cmdlineopt_;
    cmdlineoption_setdefaults (cmdlineopt);
    cmdlineoption_parse (cmdlineopt, argc, argv);

    if (cmdlineopt->co_range) {
        iprange = iprange_parse (cmdlineopt->co_range, NULL);
        if (!iprange) {
            fprintf (stderr, "error: cmdline: invalid option to -allow\n");
            exit (1);
        }
    }

    if (cmdlineopt->co_pubkey) {
        char w[1024];
        if (fastsec_retrievepubkey (privkey_fname, pubkey_fname, randseries, w, sizeof (w), errmsg)) {
            fprintf (stderr, "error: %s\n", errmsg);
            exit (1);
        }
        printf ("pubkey:\n\n%s\n\n", w);
        exit (0);
    }
    if (cmdlineopt->co_remote && cmdlineopt->co_listen) {
        fprintf (stderr, "error: cmdline: -c and -l are incompatible\n");
        exit (1);
    }
    if (!cmdlineopt->co_listen && cmdlineopt->co_nostore) {
        fprintf (stderr, "error: cmdline: -nostore is to be used with -l\n");
        exit (1);
    }
    if (cmdlineopt->co_listen && cmdlineopt->co_auth) {
        fprintf (stderr, "error: cmdline: -auth is the default with -l\n");
        exit (1);
    }
    if (!cmdlineopt->co_listen && cmdlineopt->co_noauth) {
        fprintf (stderr, "error: cmdline: -noauth is the default for -c\n");
        exit (1);
    }
    if (!cmdlineopt->co_pseudoip) {
        fprintf (stderr, "error: cmdline: -ip is required, try  tapfwd -h\n");
        exit (1);
    }
    if (!cmdlineopt->co_range && cmdlineopt->co_listen) {
        fprintf (stderr, "error: cmdline: -allow is required with -l\n");
        exit (1);
    }
    if (!cmdlineopt->co_listen) {
        if (!cmdlineopt->co_clientname) {
            fprintf (stderr, "error: cmdline: option -n is required\n");
            exit (1);
        }
        if (fastsec_validateclientname (cmdlineopt->co_clientname)) {
            fprintf (stderr, "error: cmdline: value '%s' to -n must be less than %d non-whitespace ascii\n", cmdlineopt->co_clientname, FASTSEC_CLIENTNAME_MAXLEN - 1);
            exit (1);
        }
    }

    memset (&fsinfo, '\0', sizeof (fsinfo));

    if ((fsinfo.fd_privkey = open (privkey_fname, O_RDWR | O_CREAT, 0600)) == -1)
        fatalerror (privkey_fname);
    if ((fsinfo.fd_remotepubkey = open (remotepubkey_fname, O_RDWR | O_CREAT, 0644)) == -1)
        fatalerror (remotepubkey_fname);
    if ((fsinfo.fd_pubkey = open (pubkey_fname, O_RDWR | O_CREAT, 0644)) == -1)
        fatalerror (pubkey_fname);

    devfd = configure_network (cmdlineopt);

    setup_sig_handlers ();

    if (cmdlineopt->co_listen)
        h = listen_socket ("server socket", cmdlineopt->co_listen, cmdlineopt->co_port);

    become_nobody ();

    fcntl (1, F_SETFL, O_NONBLOCK);
    fcntl (2, F_SETFL, O_NONBLOCK);

#define RESTART \
    do { \
        if (pkt_recv_count < 1UL) \
             sleep (2); \
        goto restart; \
    } while (0)

#define SHUTRESTART(m) \
    do { \
        if (sock >= 0) \
            SHUTSOCK(sock); \
        fprintf(stderr, m); \
        RESTART; \
    } while (0)

  restart:


    fs = &fs_;
    memset (fs, '\0', sizeof (*fs));

    fs->aes_encrypt = &buf1.aes;
    fs->aes_decrypt = &buf2.aes;
    fs->client_close_req_recieved = &client_close_req_recieved;
    fs->devfd = devfd;
    fs->future_packet_sent = &future_packet_sent;
    fs->last_hb_recv = &last_hb_recv;
    fs->last_hb_sent = &last_hb_sent;
    fs->non_replay_counter_encrypt = &buf1.non_replay_counter;
    fs->non_replay_counter_decrypt = &buf2.non_replay_counter;
    fs->pkt_recv_count = &pkt_recv_count;
    fs->randseries = randseries;
    fs->server = (cmdlineopt->co_listen != NULL);
    fs->server_ticket_recieved = &server_ticket_recieved;

    pkt_recv_count = 0UL;

    buf1.avail = buf2.avail = 0;
    buf1.written = buf2.written = 0;
    buf1.non_replay_counter = buf2.non_replay_counter = 0x5555555555555555ULL;
    last_hb_sent = last_hb_recv = 0L;
    assert (sock == -1);

    if (cmdlineopt->co_listen) {
        unsigned int l;
        union sockaddrin4in6 client_address;
        void *addr = NULL;
        int addrlen = 0;
        memset (&client_address, 0, l = sizeof (client_address));
        sock = accept (h, &client_address.in, &l);
        if (sock <  0) {
            RESTART;
        }
        if (sockaddr2addr (&client_address, &addr, &addrlen)) {
            SHUTRESTART ("bad address family\n");
        }
        if (!iprange) {
            /* ignore range check */
        } else if (iprange_match (iprange, addr, addrlen)) {
            /* found */
        } else {
            char is[64];
            ip_to_text (addr, addrlen, is);
            SHUTSOCK (sock);
            fprintf (stderr, "incoming address %s not in range %s\n", is, cmdlineopt->co_range);
            RESTART;
        }
        if (sock < 0) {
            SHUTRESTART ("accept fail\n");
        }
    } else {
        sock = connect_socket ("client socket", cmdlineopt->co_remote, cmdlineopt->co_port);
        if (sock < 0) {
            fprintf (stderr, "connect fail\n");
            RESTART;
        }
    }

    fsinfo.server_mode = (cmdlineopt->co_listen != NULL);
    if (fsinfo.server_mode)
        fsinfo.auth_mode = 1;
    if (cmdlineopt->co_auth)
        fsinfo.auth_mode = 1;
    if (cmdlineopt->co_noauth)
        fsinfo.auth_mode = 0;
    fsinfo.no_store = cmdlineopt->co_nostore;
    fsinfo.remotepubkey_fname = remotepubkey_fname;
    fsinfo.pubkey_fname = pubkey_fname;
    fsinfo.privkey_fname = privkey_fname;
    fsinfo.clientname = cmdlineopt->co_clientname;
    fsinfo.remotename = cmdlineopt->co_remote;
    fsinfo.reconnect_ticket = NULL;
    fsinfo.sock = sock;

    if (server_ticket_recieved && time (NULL) < (time_t) save_ticket.d.utc_seconds) {
        server_ticket_recieved = 0;
        fsinfo.reconnect_ticket = &save_ticket;
    }

    {
        long long t1, t2;
        t1 = microtime ();
        fr = fastsec_keyexchange (&fsinfo, randseries, errmsg, buf1.key, buf2.key);
        t2 = microtime ();
        printf ("handshake completed in %lld.%01lld ms\n", (t2 - t1) / 1000, ((t2 - t1) % 1000) / 100);
    }

    if (fr != FASTSEC_RESULT_SUCCESS) {
        if (fsinfo.server_mode) {
            static unsigned char once_[65536];
            unsigned int hash;
            hash = hash_str (errmsg) % (65536 * 8 - 1);
            if (!(once_[hash / 8] & (1 << (hash % 8)))) {
                fprintf (stderr, "error: %s (this error will not repeat)\n", errmsg);
                once_[hash / 8] |= (1 << (hash % 8));
            }
        } else {
            fprintf (stderr, "error: %s\n", errmsg);
        }
    }

    switch (fr) {
    case FASTSEC_RESULT_SUCCESS:
        break;
    case FASTSEC_RESULT_STORAGE_ERROR:
        exit (1);
        break;
    case FASTSEC_RESULT_SOCKET_ERROR:
    case FASTSEC_RESULT_SECURITY_ERROR:
        SHUTSOCK (sock);
        RESTART;
        break;
    }

    if (fastsec_set_aeskeys (buf1.key, &buf1.aes, buf2.key, &buf2.aes)) {
        fprintf (stderr, "error: failure setting key\n");
        exit (1);
    }

    /* hide secrets: */
    memset (buf1.key, '\0', sizeof (buf1.key));
    memset (buf2.key, '\0', sizeof (buf2.key));

    {
        int yes = 1;
        if (setsockopt (sock, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof (yes)))
            fatalerror ("setsockopt TCP_NODELAY");
        if (fcntl (devfd, F_SETFL, O_NONBLOCK))
            fatalerror2 ("fcntl O_NONBLOCK", cmdlineopt->co_dev);
        if (fcntl (sock, F_SETFL, O_NONBLOCK))
            fatalerror ("fcntl O_NONBLOCK");
    }

    printf ("connection established\n");

    for (;;) {
        int nfds = 0, idle = 0;
        fd_set rd, wr;
        FD_ZERO (&rd);
        FD_ZERO (&wr);

#define SETUP(fd, set, count, minbytes)                         \
            if (fd != -1 && (count) >= (minbytes)) {            \
                FD_SET(fd, &set);                               \
                nfds = max(nfds, fd);                           \
            }

        if (!client_close_req_recieved) {
            SETUP (devfd, rd, FASTSEC_BUF_SIZE - buf1.avail, 1500 + FASTSEC_HEADER_SIZE + FASTSEC_TRAILER_SIZE + 256);      /* 256 = fudge */
        }
        SETUP (sock, rd, FASTSEC_BUF_SIZE - buf2.avail, 1);
        SETUP (sock, wr, buf1.avail - buf1.written, 1);

        {
            int r;
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50000;
            r = select (nfds + 1, &rd, &wr, NULL, &tv);

            if (r == 0)
                idle = 1;
            else if (r == -1 && errno_TEMP ())
                continue;
        }

#define PROCESS(fd, op, set, buf, end, count)                           \
            if (fd != -1)                                               \
                if (FD_ISSET(fd, &set) || (idle && (count > 0))) {      \
                    int r;                                              \
                    r = op(fd, buf + end, count);                       \
                    if (r < 0 && errno_TEMP()) {                        \
                        /* ok */                                        \
                    } else if (r < 1) {                                 \
                        SHUTRESTART (#op " error - restarting\n");      \
                    } else                                              \
                        end += r;                                       \
                }

        {
            enum fastsec_housekeeping_result r;
            int result_len = 0;

            r = fastsec_housekeeping (fs, &buf1.data[buf1.avail], FASTSEC_BUF_SIZE - buf1.avail, &result_len);

            switch (r) {
            case FASTSEC_HOUSEKEEPING_RESULT_SUCCESS:
                buf1.avail += result_len;
                break;
            case FASTSEC_HOUSEKEEPING_RESULT_FAIL_HEARTBEAT_TIMEOUT:
                SHUTRESTART ("timeout - restarting\n");
                break;
            case FASTSEC_HOUSEKEEPING_RESULT_FAIL_BUF_TOO_SMALL:
                /* this is rare. it is not problem. */
                break;
            }
        }

        if (FD_ISSET (devfd, &rd)) {
            int r;
            r = read (devfd, buf1.data + buf1.avail + FASTSEC_HEADER_SIZE, FASTSEC_BUF_SIZE - buf1.avail - (FASTSEC_HEADER_SIZE + FASTSEC_TRAILER_SIZE));
            if (r == -1 && errno_TEMP ()) {
                /* ignore */
            } else if (r < 1) {
                fatalerror2 ("read", cmdlineopt->co_dev);
            } else {
                make_encrypted_packet (&buf1, randseries, FASTSEC_PKTTYPE_DATA, r);
            }
        }

        PROCESS (sock, read, rd, buf2.data, buf2.avail, FASTSEC_BUF_SIZE - buf2.avail);

        {
            enum fastsec_result_decrypt err_decrypt;
            enum fastsec_result_avail err_avail = FASTSEC_RESULT_AVAIL_SUCCESS;
            int read_count;

            err_avail = fastsec_process_ciphertext (fs, buf2.data + buf2.written, buf2.avail - buf2.written, &err_decrypt, &read_count);

            switch (err_avail) {
            case FASTSEC_RESULT_AVAIL_SUCCESS:
                buf2.written += read_count;
                break;
            case FASTSEC_RESULT_AVAIL_SUCCESS_NEED_MORE_INPUT:
                buf2.written += read_count;
                memmove (buf2.data, buf2.data + buf2.written, buf2.avail - buf2.written);
                buf2.avail -= buf2.written;
                buf2.written = 0;
                break;
            case FASTSEC_RESULT_AVAIL_FAIL_LENGTH_TOO_LARGE:
                SHUTRESTART ("bad length\n");
            case FASTSEC_RESULT_AVAIL_FAIL_DECRYPT:
                switch (err_decrypt) {
                case FASTSEC_RESULT_DECRYPT_SUCCESS:
                    assert (!"not possible");
                    break;
                case FASTSEC_RESULT_DECRYPT_FAIL_PKTTYPE:
                    SHUTRESTART ("packet type check failed\n");
                case FASTSEC_RESULT_DECRYPT_FAIL_LEN:
                    SHUTRESTART ("length len check failed\n");
                case FASTSEC_RESULT_DECRYPT_FAIL_CHKSUM:
                    SHUTRESTART ("checksum failed\n");
                case FASTSEC_RESULT_DECRYPT_FAIL_REPLAY:
                    SHUTRESTART ("replay attack detected\n");
                }
                break;
            case FASTSEC_RESULT_AVAIL_FAIL_WRITE:
                SHUTRESTART ("writedev error - restarting\n");
            case FASTSEC_RESULT_AVAIL_FAIL_CLIENTCLOSERESPONSE_INVALID_PKT_SIZE:
                SHUTRESTART ("client received CLIENTCLOSERESPONSE invalid packet size\n");
            case FASTSEC_RESULT_AVAIL_FAIL_CLIENT_RCVD_CLIENTCLOSEREQ:
                SHUTRESTART ("client received invalid packet CLIENTCLOSEREQ\n");
            }
        }

        PROCESS (sock, write, wr, buf1.data, buf1.written, buf1.avail - buf1.written);

        /* check if write data has caught read data */
        if (buf1.written == buf1.avail) {
            buf1.written = buf1.avail = 0;
            if (client_close_req_recieved) {
                assert (cmdlineopt->co_listen);
                SHUTRESTART ("server write CLIENTCLOSERESPONSE\n");
            }
        }

        if (buf2.written == buf2.avail)
            buf2.written = buf2.avail = 0;
    }

    return 0;
}

