#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

#include <fcntl.h>


#include "aes.h"
#include "fastsec.h"
#include "randseries.h"

/* #define TICKET */


#ifdef __GNUC__
#define WARN_UNUSED             __attribute__((warn_unused_result))
#else
#define WARN_UNUSED             
#endif



#define ERRMSG_LEN              160


static int fastsec_has_hw_aes = 0;


/* y² = x³ + 486662x² + x */
extern int curve25519 (unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

/* y² + x² = 1 − 39081x²y² */
extern int curve448 (unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);



#define CURVE_KEYLEN_BOTH               (32 + 56)

struct eckey {
    unsigned char v25519[32];
    unsigned char v448[56];
} __attribute__ ((packed));

struct client_hello {
    unsigned char client_hello_version;
    char clientname[FASTSEC_CLIENTNAME_MAXLEN];
    struct eckey pubkey;                /* stored on file-system and verified */
    struct eckey transient_pubkey;      /* generated new for each session */
#ifdef TICKET
    unsigned char signed_ticket[16];
#endif
} __attribute__ ((packed));

struct server_hello {
    unsigned char server_hello_version;
    struct eckey pubkey;
    struct eckey transient_pubkey;
#ifdef TICKET
    unsigned char next_keymaterial[64];
    unsigned char reconnect_ticket[16];
#endif
} __attribute__ ((packed));


struct handshakedata {
    struct client_hello ch;
    struct server_hello sh;
    struct eckey privkey;
    struct eckey transient_privkey;
    struct eckey shared_secret;
    struct eckey trnsnt_secret;
    unsigned char transient_key1[FASTSEC_KEY_SZ];
    unsigned char transient_key2[FASTSEC_KEY_SZ];
};



static void xor_mem (unsigned char *a, const unsigned char *b, int l)
{
    int i;
    for (i = 0; i < l; i++)
        a[i] ^= b[i];
}

static void write_uint (void *out_, unsigned long long v, int l)
{
    unsigned char *out;
    out = (unsigned char *) out_;
    out += (l - 1);
    do {
        *out-- = (v & 0xFF);
        v >>= 8;
    } while (--l);
}

static unsigned long long read_uint (const void *in_, int l)
{
    unsigned long long v = 0UL;
    const unsigned char *in;
    in = (unsigned char *) in_;
    do {
        v <<= 8;
        v |= (*in++ & 0xff);
    } while (--l);
    return v;
}

static void write_hex_str (char *t, const unsigned char *d, int l)
{
    const char *hex = "0123456789abcdef";
    int i;
    for (i = 0; i < l; i++) {
        t[i * 2 + 0] = hex[d[i] >> 4];
        t[i * 2 + 1] = hex[d[i] & 15];
    }
    t[l * 2] = '\0';
}

#if defined(__GNUC__) || defined(__INTEL_COMPILER) && !defined(_MSC_VER)
static void err_sprintf (char *errmsg, const char *fmt, ...) __attribute__((format(__printf__, 2, 3), __unused__));
#else
static void err_sprintf (char *errmsg, const char *fmt, ...);
#endif

static void err_sprintf (char *errmsg, const char *fmt, ...)
{
    va_list ap;
    va_start (ap, fmt);
    vsnprintf (errmsg, ERRMSG_LEN, fmt, ap);
    va_end (ap);
}

static int WARN_UNUSED fd_position (int fd, const char *fname, int append, char *errmsg)
{
    if (fcntl (fd, F_SETFL, (append ? (O_RDWR | O_APPEND) : O_RDWR))) {
        err_sprintf (errmsg, "fnctl: %s: %s", fname, strerror (errno));
        return 1;
    }
    if (!append && lseek (fd, 0L, SEEK_SET) != 0) {
        err_sprintf (errmsg, "lseek: %s: %s", fname, strerror (errno));
        return 1;
    }
    return 0;
}

static int WARN_UNUSED write_hex_to_file (int fd, const char *fname, const unsigned char *d, int l, char *errmsg)
{
    char t[256];
    if (fd_position (fd, fname, 0, errmsg))
        return 1;
    write_hex_str (t, d, l);
    t[l * 2] = '\n';
    if (write (fd, t, l * 2 + 1) != l * 2 + 1) {
        err_sprintf (errmsg, "write: %s: %s", fname, strerror (errno));
        return 1;
    }
    return 0;
}

static int WARN_UNUSED read_hex_str (const char *t, int l, unsigned char *d)
{
    int c = 0;
    int i;
    const char *hex = "0123456789abcdef0123456789ABCDEF";
    for (i = 0; i < l * 2; i++) {
        const char *q;
        if (!t[i])
            return 1;
        q = strchr (hex, t[i]);
        if (!q)
            return 1;
        c <<= 4;
        c |= ((int) (q - hex) & 15);
        if ((i % 2))
            d[i / 2] = c;
    }
    return 0;
}

static int WARN_UNUSED read_hex_from_file (int fd, int *empty, const char *fname, unsigned char *d, int l, char *errmsg)
{
    struct stat st;
    char t[1024];
    memset (&st, '\0', sizeof (st));
    if (fstat (fd, &st)) {
        err_sprintf (errmsg, "fstat: %s: %s", fname, strerror (errno));
        return 1;
    }
    if (!st.st_size) {
        *empty = 1;
        return 0;
    }
    if (fd_position (fd, fname, 0, errmsg))
        return 1;
    memset (t, '\0', sizeof (t));
    if (read (fd, t, l * 2) != l * 2) {
        err_sprintf (errmsg, "%s: short read", fname);
        return 1;
    }
    if (read_hex_str (t, l, d)) {
        err_sprintf (errmsg, "%s: invalid format", fname);
        return 1;
    }
    printf ("successfully loaded private key from file %s\n", fname);
    *empty = 0;
    return 0;
}


static void rand_private_key (struct randseries *s, struct eckey *privkey)
{
    randseries_bytes (s, privkey, CURVE_KEYLEN_BOTH);

/* follow DJB instructions: */
    privkey->v25519[0] &= 248;
    privkey->v25519[31] &= 127;
    privkey->v25519[31] |= 64;
}

/* returns 1 if a new private key was generated */
static int WARN_UNUSED make_private_key (int fd, int *new_key, const char *fname, struct randseries *s, struct eckey *privkey, char *errmsg)
{
    int empty = 0;
    *new_key = 0;
    if (read_hex_from_file (fd, &empty, fname, (unsigned char *) privkey, CURVE_KEYLEN_BOTH, errmsg))
        return 1;
    if (empty) {
        rand_private_key (s, privkey);
        if (write_hex_to_file (fd, fname, (const unsigned char *) privkey, CURVE_KEYLEN_BOTH, errmsg))
            return 1;
        *new_key = 1;
    }
    return 0;
}

struct fdcache {
    int avail;
    int written;
    char buf[32];
};

static int WARN_UNUSED fd_gets (int fd, char *out, int len, struct fdcache *cache)
{
    int got_eol = 0;
    do {
        if (cache->avail <= 0 || cache->avail == cache->written) {
            int r;
            r = read (fd, cache->buf, sizeof (cache->buf));
            if (r <= 0)
                return 1;
            cache->avail = r;
            cache->written = 0;
        }
        while (cache->written < cache->avail) {
            char ch;
            ch = cache->buf[cache->written++];
            if (len > 1) {
                *out++ = ch;
                len--;
            }
            if (ch == '\n') {
                got_eol = 1;
                break;
            }
        }
    } while (!got_eol);
    *out = '\0';
    return 0;
}

static enum fastsec_result store_remote_public_key (int fd, const char *fname, const char *host, struct eckey *pubkey, int no_new_keys, int no_store, char *errmsg)
{
    int line = 0;
    char t[1024];
    struct fdcache cache;
    memset (&cache, '\0', sizeof (cache));
    if (fd_position (fd, fname, 0, errmsg))
        return FASTSEC_RESULT_STORAGE_ERROR;
    for (;;) {
        unsigned char pubkeycmp[CURVE_KEYLEN_BOTH];
        unsigned char *p;
        memset (t, '\0', sizeof (t));
        line++;
        if (fd_gets (fd, t, sizeof (t) - 1, &cache))
            break;
        p = (unsigned char *) t;
        while (*p && *p <= ' ')
            p++;
        if (strncmp ((const char *) p, host, strlen (host)))
            continue;
        p += strlen (host);
        if (!(*p == '\t' || *p == ' '))
            continue;
        while (*p && *p <= ' ')
            p++;
        if (read_hex_str ((const char *) p, CURVE_KEYLEN_BOTH, pubkeycmp)) {
            err_sprintf (errmsg, "error: %s:%d: invalid format", fname, line);
            return FASTSEC_RESULT_STORAGE_ERROR;
        }
        if (memcmp ((void *) pubkey, pubkeycmp, CURVE_KEYLEN_BOTH)) {
            err_sprintf (errmsg, "error: %s:%d: public key for remote '%s' does not match", fname, line, host);
            return FASTSEC_RESULT_SECURITY_ERROR;
        }
        printf ("%s:%d: public key for remote '%s' successfully matched\n", fname, line, host);
        return FASTSEC_RESULT_SUCCESS;
    }

    if (no_store) {
        return FASTSEC_RESULT_SUCCESS;
    }

    if (no_new_keys) {
        err_sprintf (errmsg, "error: %s:%d: public key for remote '%s' does not exist (see -auth and -noauth options)", fname, line, host);
        return FASTSEC_RESULT_SECURITY_ERROR;
    }

    if (fd_position (fd, fname, 1, errmsg))
        return FASTSEC_RESULT_STORAGE_ERROR;
    strcpy (t, host);
    strcat (t, "\t");
    write_hex_str (t + strlen (t), (const unsigned char *) pubkey, CURVE_KEYLEN_BOTH);
    strcat (t, "\n");
    printf ("%s:%d: stored new public key for '%s'\n", fname, line, host);
    if ((int) write (fd, t, strlen (t)) != (int) strlen (t)) {
        err_sprintf (errmsg, "%s: writing to key store: %s", fname, strerror (errno));
        return FASTSEC_RESULT_STORAGE_ERROR;
    }
    return FASTSEC_RESULT_SUCCESS;
}

static int WARN_UNUSED write_public_key (int fd, const char *fname, struct eckey *pubkey, char *errmsg)
{
    return write_hex_to_file (fd, fname, (const unsigned char *) pubkey, CURVE_KEYLEN_BOTH, errmsg);
}

static int WARN_UNUSED make_public_private_key (int fd_priv, const char *fname_priv, int fd_pub, const char *fname_pub, struct randseries *s, struct eckey *privkey, struct eckey *pubkey, char *errmsg)
{
    struct stat st;
    int new_key;
    struct eckey basepoint;

    if (make_private_key (fd_priv, &new_key, fname_priv, s, privkey, errmsg))
        return 1;

    memset (basepoint.v25519, '\0', sizeof (basepoint.v25519));
    basepoint.v25519[0] = 9;
    curve25519 (pubkey->v25519, privkey->v25519, basepoint.v25519);

    memset (basepoint.v448, '\0', sizeof (basepoint.v448));
    basepoint.v448[0] = 5;
    curve448 (pubkey->v448, privkey->v448, basepoint.v448);

    memset (&st, '\0', sizeof (st));
    if (new_key || fstat (fd_pub, &st) || st.st_size < CURVE_KEYLEN_BOTH * 2)
        if (write_public_key (fd_pub, fname_pub, pubkey, errmsg))
            return 1;

    return 0;
}

static void make_transient_public_private_key (struct randseries *s, struct eckey *privkey, struct eckey *pubkey)
{
    struct eckey basepoint;

    rand_private_key (s, privkey);

    memset (basepoint.v25519, '\0', sizeof (basepoint.v25519));
    basepoint.v25519[0] = 9;
    curve25519 (pubkey->v25519, privkey->v25519, basepoint.v25519);

    memset (basepoint.v448, '\0', sizeof (basepoint.v448));
    basepoint.v448[0] = 5;

    curve448 (pubkey->v448, privkey->v448, basepoint.v448);
}

int fastsec_validateclientname (const char *clientname)
{
    const char *q;
    if (strlen (clientname) > FASTSEC_CLIENTNAME_MAXLEN - 1)
        return 1;
    for (q = clientname; *q; q++)
        if (*q <= ' ' || *q > '~')
            return 1;
    return 0;
}



/* test vector from https://tools.ietf.org/html/rfc7748 */
static void test_curve448 (void)
{
    const char *alice_privkey = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
    const char *bob_privkey = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
    const char *shared_secret = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

    unsigned char basepoint[56];

    unsigned char a[56];
    unsigned char b[56];

    unsigned char puba[56];
    unsigned char pubb[56];

    unsigned char outa[56];
    unsigned char outb[56];
    unsigned char outcmp[56];

    if (read_hex_str (alice_privkey, 56, a))
        exit (1);
    if (read_hex_str (bob_privkey, 56, b))
        exit (1);
    if (read_hex_str (shared_secret, 56, outcmp))
        exit (1);

    memset (basepoint, '\0', sizeof (basepoint));
    basepoint[0] = 5;

    curve448 (puba, a, basepoint);
    curve448 (pubb, b, basepoint);

    curve448 (outa, a, pubb);
    curve448 (outb, b, puba);

    assert (!memcmp (outa, outcmp, 56));
    assert (!memcmp (outb, outcmp, 56));
}

/* test vector from https://tools.ietf.org/html/rfc7748 */
static void test_curve25519 (void)
{
    const char *alice_privkey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const char *bob_privkey = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const char *shared_secret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    unsigned char basepoint[32];

    unsigned char a[32];
    unsigned char b[32];

    unsigned char puba[32];
    unsigned char pubb[32];

    unsigned char outa[32];
    unsigned char outb[32];
    unsigned char outcmp[32];

    if (read_hex_str (alice_privkey, 32, a))
        exit (1);
    if (read_hex_str (bob_privkey, 32, b))
        exit (1);
    if (read_hex_str (shared_secret, 32, outcmp))
        exit (1);

    memset (basepoint, '\0', sizeof (basepoint));
    basepoint[0] = 9;

    curve25519 (puba, a, basepoint);
    curve25519 (pubb, b, basepoint);

    curve25519 (outa, a, pubb);
    curve25519 (outb, b, puba);

    assert (!memcmp (outa, outcmp, 32));
    assert (!memcmp (outb, outcmp, 32));
}

void fastsec_runcurvetests (void)
{
    test_curve448 ();
    test_curve25519 ();
}

int fastsec_retrievepubkey (const char *privkey_fname, const char *pubkey_fname, struct randseries *randseries, char *out, int outlen,
                            char *errmsg)
{
    int fd_privkey = -1;
    int fd_pubkey = -1;
    struct eckey pubkey;
    struct eckey privkey;

    memset (out, '\0', outlen);
    if ((fd_privkey = open (privkey_fname, O_RDWR | O_CREAT, 0600)) == -1) {
        /* this means we don't access (not running as root), so we should
         * just read the public key from its file: */
        FILE *f;
        printf ("%s: %s\n", privkey_fname, strerror (errno));
        f = fopen (pubkey_fname, "r");
        if (!f) {
            err_sprintf (errmsg, "%s: %s", pubkey_fname, strerror (errno));
            return 1;
        }
        if (!fgets (out, outlen, f)) {
            err_sprintf (errmsg, "%s: short read", pubkey_fname);
            return 1;
        }
        if (strlen (out) <= CURVE_KEYLEN_BOTH * 2) {
            err_sprintf (errmsg, "%s: short file", pubkey_fname);
            return 1;
        }
    } else {
        struct stat st1, st2;
        memset (&st1, '\0', sizeof (st1));
        memset (&st2, '\0', sizeof (st2));
        if (fstat (fd_privkey, &st1)) {
            err_sprintf (errmsg, "%s: %s", privkey_fname, strerror (errno));
            return 1;
        }
        if (!stat (pubkey_fname, &st2)) {
            if (st1.st_uid != st2.st_uid) {
                err_sprintf (errmsg, "%s and %s have different ownership", privkey_fname, pubkey_fname);
                return 1;
            }
        }
        if ((fd_pubkey = open (pubkey_fname, O_RDWR | O_CREAT, 0644)) == -1) {
            err_sprintf (errmsg, "%s: %s", pubkey_fname, strerror (errno));
            return 1;
        }
        if (make_public_private_key (fd_privkey, privkey_fname, fd_pubkey, pubkey_fname, randseries, &privkey, &pubkey, errmsg))
            return 1;
        write_hex_str (out, (const unsigned char *) &pubkey, CURVE_KEYLEN_BOTH);
    }
    return 0;
}

void fastsec_aesoneblock (const unsigned char *key, int key_len, const unsigned char *in, unsigned char *out)
{
    struct aes_key_st aes;
    if (aes_set_encrypt_key (key, key_len * 8, &aes)) {
        fprintf (stderr, "error: failure setting key\n");
        exit (1);
    }
    aes_encrypt (in, out, &aes);
    memset (&aes, '\0', sizeof (aes));
}

#define errno_TEMP()            (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR || errno == EINPROGRESS)

static int WARN_UNUSED readwriteall (const int one_for_write, const int sock, void *const buf_, const int len_, const int timeout, char * const errmsg)
{
    unsigned char *buf;
    int tot = 0, len = len_;
    buf = (unsigned char *) buf_;

    time_t t1, t2;
    time (&t1);

    *errmsg = '\0';

    while (len > 0) {
        int c;
        if (one_for_write)
            c = write (sock, buf, len);
        else
            c = read (sock, buf, len);
        if (c > 0) {
            tot += c;
            buf += c;
            len -= c;
            continue;
        }
        if (c < 0 && errno_TEMP ()) {
            struct timeval tv;
            int sr;
            fd_set the_fdset;

          select_again:
            time (&t2);
            if (t2 - t1 > timeout) {
                err_sprintf (errmsg, "timeout waiting for %s", one_for_write ? "write" : "read");
                return -1;
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;
            FD_ZERO (&the_fdset);
            FD_SET (sock, &the_fdset);
            if (one_for_write)
                sr = select (sock + 1, NULL, &the_fdset, NULL, &tv);
            else
                sr = select (sock + 1, &the_fdset, NULL, NULL, &tv);
            if (sr > 0)
                continue;
            if (sr < 0 && errno_TEMP ())
                goto select_again;
            if (sr == 0)
                goto select_again;
            if (sr < 0) {
                err_sprintf (errmsg, "file descriptor error: %s", strerror (errno));
                return -1;
            }
        } else if (c == 0) {
            strcpy (errmsg, "remote closed connection");
            return -1;
        } else {
            err_sprintf (errmsg, "socket error: %s", strerror (errno));
            return -1;
        }
    }
    return tot;
}

static int WARN_UNUSED writeall (int sock, void *buf, int len, char *errmsg)
{
    return readwriteall (1, sock, buf, len, 5, errmsg);
}

static int WARN_UNUSED readall (int sock, void *buf, int len, char *errmsg)
{
    return readwriteall (0, sock, buf, len, 20, errmsg);
}

static void keydgst (const unsigned char *egg_white, const unsigned char *egg_yolk, unsigned char *out)
{
    if (FASTSEC_KEY_SZ == 16) {
/* for backward compatibility with a previous version: */
        fastsec_aesoneblock (egg_yolk, 16, egg_white, out);
    } else {
        memcpy (out, egg_white, FASTSEC_KEY_SZ);
        fastsec_aesoneblock (egg_white, FASTSEC_KEY_SZ, egg_yolk, out);
    }
}

void fastsec_init (void)
{
    fastsec_runcurvetests ();

    if (FASTSEC_KEY_SZ == 32)
        fastsec_has_hw_aes = aes_has_aesni ();
    else
        fastsec_has_hw_aes = 0;
}

int fastsec_set_aeskeys (unsigned char *key1, struct aes_key_st *aes1, unsigned char *key2, struct aes_key_st *aes2)
{
    if (fastsec_has_hw_aes) {
        if (aes_ni_set_encrypt_key (key1, aes1) || aes_ni_set_decrypt_key (key2, aes2))
            return 1;
    } else {
        if (aes_set_encrypt_key (key1, FASTSEC_KEY_SZ * 8, aes1) || aes_set_decrypt_key (key2, FASTSEC_KEY_SZ * 8, aes2))
            return 1;
    }
    printf ("fastsec_set_aeskeys success, fastsec_has_hw_aes=%d, sizeof(long)=%d\n", fastsec_has_hw_aes, (int) sizeof (long));
    return 0;
}

enum fastsec_result fastsec_keyexchange (struct fastsec_keyexchange_info *info, struct randseries *randseries, char *errmsg, unsigned char *key1, unsigned char *key2)
{
    struct handshakedata hd;
    char errmsg_[ERRMSG_LEN];
    enum fastsec_result r = FASTSEC_RESULT_SUCCESS;

    memset (&hd, '\0', sizeof (hd));
    memset (key1, '\0', FASTSEC_KEY_SZ);
    memset (key2, '\0', FASTSEC_KEY_SZ);

#define err(e,prn)   do { r = e; prn; goto errout; } while (0)

    if (info->server_mode) {
        if (readall (info->sock, &hd.ch, sizeof (hd.ch), errmsg_) != sizeof (hd.ch))
            err (FASTSEC_RESULT_SOCKET_ERROR, err_sprintf (errmsg, "handshake: %s", errmsg_));
        hd.ch.clientname[FASTSEC_CLIENTNAME_MAXLEN - 1] = '\0';
        if (fastsec_validateclientname (hd.ch.clientname))
            err (FASTSEC_RESULT_SECURITY_ERROR, strcpy (errmsg, "invalid client name in handshake"));
        if ((r = store_remote_public_key (info->fd_remotepubkey, info->remotepubkey_fname, hd.ch.clientname, &hd.ch.pubkey, info->auth_mode, info->no_store, errmsg)) != FASTSEC_RESULT_SUCCESS)
            return r;
        printf ("received client hello\n");
        if (make_public_private_key (info->fd_privkey, info->privkey_fname, info->fd_pubkey, info->pubkey_fname, randseries, &hd.privkey, &hd.sh.pubkey, errmsg))
            err (FASTSEC_RESULT_STORAGE_ERROR,);
        make_transient_public_private_key (randseries, &hd.transient_privkey, &hd.sh.transient_pubkey);
        if (writeall (info->sock, &hd.sh, sizeof (hd.sh), errmsg_) != sizeof (hd.sh))
            err (FASTSEC_RESULT_SOCKET_ERROR, err_sprintf (errmsg, "handshake: %s", errmsg_));
        printf ("sent server hello\n");
        curve25519 (hd.shared_secret.v25519, hd.privkey.v25519, hd.ch.pubkey.v25519);
        curve448 (hd.shared_secret.v448, hd.privkey.v448, hd.ch.pubkey.v448);
        curve25519 (hd.trnsnt_secret.v25519, hd.transient_privkey.v25519, hd.ch.transient_pubkey.v25519);
        curve448 (hd.trnsnt_secret.v448, hd.transient_privkey.v448, hd.ch.transient_pubkey.v448);

/* for backward compatibility with a previous version: */
#define JUSTIFY(l,b)    (((l) - (b)) < (b) ? ((l) - (b)) : (b))
#define LEFT(a,b)       &a[0]
#define RGHT(a,b)       &a[JUSTIFY(sizeof(a),b)]

        keydgst (LEFT (hd.shared_secret.v448, FASTSEC_KEY_SZ), LEFT (hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), key1);
        keydgst (RGHT (hd.shared_secret.v448, FASTSEC_KEY_SZ), RGHT (hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), key2);
        keydgst (LEFT (hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), LEFT (hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), hd.transient_key1);
        keydgst (RGHT (hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), RGHT (hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), hd.transient_key2);
        xor_mem (key1, hd.transient_key1, FASTSEC_KEY_SZ);
        xor_mem (key2, hd.transient_key2, FASTSEC_KEY_SZ);
    } else {
        if (make_public_private_key (info->fd_privkey, info->privkey_fname, info->fd_pubkey, info->pubkey_fname, randseries, &hd.privkey, &hd.ch.pubkey, errmsg))
            err (FASTSEC_RESULT_STORAGE_ERROR,);
        make_transient_public_private_key (randseries, &hd.transient_privkey, &hd.ch.transient_pubkey);
        strcpy (hd.ch.clientname, info->clientname);
        if (writeall (info->sock, &hd.ch, sizeof (hd.ch), errmsg_) != sizeof (hd.ch))
            err (FASTSEC_RESULT_SOCKET_ERROR, err_sprintf (errmsg, "handshake: %s", errmsg_));
        printf ("sent client hello, %d bytes\n", (int) sizeof (hd.ch));
        if (readall (info->sock, &hd.sh, sizeof (hd.sh), errmsg_) != sizeof (hd.sh))
            err (FASTSEC_RESULT_SOCKET_ERROR, err_sprintf (errmsg, "handshake: %s", errmsg_));
        if ((r = store_remote_public_key (info->fd_remotepubkey, info->remotepubkey_fname, info->remotename, &hd.sh.pubkey, info->auth_mode, 0, errmsg)) != FASTSEC_RESULT_SUCCESS)
            return r;
        printf ("received server hello\n");
        curve25519 (hd.shared_secret.v25519, hd.privkey.v25519, hd.sh.pubkey.v25519);
        curve448 (hd.shared_secret.v448, hd.privkey.v448, hd.sh.pubkey.v448);
        curve25519 (hd.trnsnt_secret.v25519, hd.transient_privkey.v25519, hd.sh.transient_pubkey.v25519);
        curve448 (hd.trnsnt_secret.v448, hd.transient_privkey.v448, hd.sh.transient_pubkey.v448);
        keydgst (LEFT (hd.shared_secret.v448, FASTSEC_KEY_SZ), LEFT (hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), key2);
        keydgst (RGHT (hd.shared_secret.v448, FASTSEC_KEY_SZ), RGHT (hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), key1);
        keydgst (LEFT (hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), LEFT (hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), hd.transient_key2);
        keydgst (RGHT (hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), RGHT (hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), hd.transient_key1);
        xor_mem (key2, hd.transient_key2, FASTSEC_KEY_SZ);
        xor_mem (key1, hd.transient_key1, FASTSEC_KEY_SZ);
    }

    /* hide secrets: */
    memset (&hd, '\0', sizeof (hd));
    return r;

  errout:
    /* hide secrets: */
    memset (&hd, '\0', sizeof (hd));
    memset (key1, '\0', FASTSEC_KEY_SZ);
    memset (key2, '\0', FASTSEC_KEY_SZ);
    return r;
}


int fastsec_encrypt_packet (char *out, uint64_t *non_replay_counter, struct aes_key_st *aes, struct randseries *s, int pkttype, int len)
{
    struct header *h;
    struct trailer *t;
    unsigned char iv[FASTSEC_BLOCK_SZ];

    h = (struct header *) out;

    write_uint (&h->hdr.pkttype, pkttype, sizeof (h->hdr.pkttype));
    write_uint (&h->hdr.length, FASTSEC_ROUND (len), sizeof (h->hdr.length));
    write_uint (&h->hdr_chk.non_replay_counter, *non_replay_counter, sizeof (h->hdr_chk.non_replay_counter));
    write_uint (&h->hdr_chk.pkttype, pkttype, sizeof (h->hdr_chk.pkttype));
    write_uint (&h->hdr_chk.length, len, sizeof (h->hdr_chk.length));

    (*non_replay_counter)++;

    randseries_bytes (s, iv, FASTSEC_BLOCK_SZ);
    memcpy (h->iv, iv, FASTSEC_BLOCK_SZ);

    /* zero trailing bytes */
    memset (((unsigned char *) &h->hdr_chk) + FASTSEC_FULLLEN (len), '\0', FASTSEC_CRYPTLEN (len) - FASTSEC_FULLLEN (len));

    if (fastsec_has_hw_aes)
        aes_ni_cbc_encrypt ((const unsigned char *) &h->hdr_chk, (unsigned char *) &h->hdr_chk, FASTSEC_CRYPTLEN (len), aes, iv);
    else
        aes_cbc128_encrypt ((const unsigned char *) &h->hdr_chk, (unsigned char *) &h->hdr_chk, FASTSEC_CRYPTLEN (len), aes, iv);

    t = (struct trailer *) &out[FASTSEC_HEADER_SIZE + FASTSEC_ROUND (len)];
    memcpy (t->chksum, iv, FASTSEC_BLOCK_SZ);

    return FASTSEC_HEADER_SIZE + FASTSEC_ROUND (len) + FASTSEC_TRAILER_SIZE;
}


enum fastsec_result_decrypt fastsec_decrypt_packet (char *in, int len_round, int *pkttype, uint64_t *non_replay_counter, struct aes_key_st *aes, int *len)
{
    struct header *h;
    struct trailer *t;
    uint64_t non_replay_counter_chk;
    int pkttype_chk;

    h = (struct header *) in;

    *pkttype = read_uint (&h->hdr.pkttype, sizeof (h->hdr.pkttype));

    if (fastsec_has_hw_aes)
        aes_ni_cbc_decrypt ((const unsigned char *) &h->hdr_chk, (unsigned char *) &h->hdr_chk, len_round + sizeof (struct pkthdr_chk), aes, h->iv);
    else
        aes_cbc128_decrypt ((const unsigned char *) &h->hdr_chk, (unsigned char *) &h->hdr_chk, len_round + sizeof (struct pkthdr_chk), aes, h->iv);

    non_replay_counter_chk = read_uint (&h->hdr_chk.non_replay_counter, sizeof (h->hdr_chk.non_replay_counter));
    pkttype_chk = read_uint (&h->hdr_chk.pkttype, sizeof (h->hdr_chk.pkttype));
    *len = read_uint (&h->hdr_chk.length, sizeof (h->hdr_chk.length));

    t = (struct trailer *) &in[len_round + FASTSEC_HEADER_SIZE];

    if (pkttype_chk != *pkttype)
        return FASTSEC_RESULT_DECRYPT_FAIL_PKTTYPE;
    if (len_round != FASTSEC_ROUND (*len))
        return FASTSEC_RESULT_DECRYPT_FAIL_LEN;
    if (memcmp (t->chksum, h->iv, sizeof (t->chksum)))
        return FASTSEC_RESULT_DECRYPT_FAIL_CHKSUM;
    if (*non_replay_counter != non_replay_counter_chk)
        return FASTSEC_RESULT_DECRYPT_FAIL_REPLAY;

    (*non_replay_counter)++;
    return FASTSEC_RESULT_DECRYPT_SUCCESS;
}

void fastsec_construct_ticket (union reconnect_ticket *ticket)
{
    unsigned long long expire_time;
    memset (ticket, '\0', sizeof (*ticket));

/* construct ticket */

    expire_time = time(NULL);
    expire_time += 30 * 60;
    write_uint (&ticket->d.utc_seconds, expire_time, sizeof (ticket->d.utc_seconds));
}






enum fastsec_result_avail fastsec_process_ciphertext (struct fastsec *fs, char *data, int datalen, enum fastsec_result_decrypt *err_decrypt, int *read_count)
{
    time_t now;

    time (&now);
    *read_count = 0;

    while (datalen > 0) {
        int len_round, len, pkttype;
        enum fastsec_result_decrypt err;
        struct header *h;

        if (datalen < FASTSEC_HEADER_SIZE)
            return FASTSEC_RESULT_AVAIL_SUCCESS_NEED_MORE_INPUT;

        h = (struct header *) data;

        len_round = read_uint (&h->hdr.length, sizeof (h->hdr.length));

        if (len_round > FASTSEC_BUF_SIZE - (FASTSEC_HEADER_SIZE + FASTSEC_ROUND (0) + FASTSEC_TRAILER_SIZE))
            return FASTSEC_RESULT_AVAIL_FAIL_LENGTH_TOO_LARGE;

        if (datalen < FASTSEC_HEADER_SIZE + len_round + FASTSEC_TRAILER_SIZE)
            return FASTSEC_RESULT_AVAIL_SUCCESS_NEED_MORE_INPUT;

        switch ((err = fastsec_decrypt_packet (data, len_round, &pkttype, &fs->non_replay_counter_decrypt, &fs->aes_decrypt, &len))) {
        case FASTSEC_RESULT_DECRYPT_SUCCESS:
            break;
        default:
            *err_decrypt = err;
            return FASTSEC_RESULT_AVAIL_FAIL_DECRYPT;
        }

        fs->pkt_recv_count++;

        switch (pkttype) {
        case FASTSEC_PKTTYPE_DATA:
            if ((*fs->process_plaintext) (fs->user_data1, fs->user_data2, data + FASTSEC_HEADER_SIZE, len))
                return FASTSEC_RESULT_AVAIL_FAIL_PROCESS_PLAINTEXT;
            break;
        case FASTSEC_PKTTYPE_HEARTBEAT:
            *fs->last_hb_recv = now;
            break;
        case FASTSEC_PKTTYPE_RESPONSETOCLOSEREQ:
            if (len != sizeof (*fs->save_ticket))
                return FASTSEC_RESULT_AVAIL_FAIL_CLIENTCLOSERESPONSE_INVALID_PKT_SIZE;
            *fs->server_ticket_recieved = 1;
            memcpy (fs->save_ticket, data + FASTSEC_HEADER_SIZE, sizeof (*fs->save_ticket));
            fs->save_ticket->d.utc_seconds = read_uint (&fs->save_ticket->d.utc_seconds, sizeof (fs->save_ticket->d.utc_seconds));
printf ("TBD\n");
return FASTSEC_RESULT_AVAIL_SUCCESS;
            break;
        case FASTSEC_PKTTYPE_CLIENTCLOSEREQ:
            if (fs->server) {
                union reconnect_ticket ticket;
                *fs->client_close_req_recieved = 1;
                fastsec_construct_ticket (&ticket);
                memcpy (data + FASTSEC_HEADER_SIZE, &ticket, sizeof (ticket));
printf ("TBD\n");
//                 make_encrypted_packet (&buf1, randseries, FASTSEC_PKTTYPE_RESPONSETOCLOSEREQ, FASTSEC_BLOCK_SZ);
            } else {
                return FASTSEC_RESULT_AVAIL_FAIL_CLIENT_RCVD_CLIENTCLOSEREQ;
            }
            break;
        default:
            /* ignore unknown packet types for future versions */
            break;
        }
        data += FASTSEC_HEADER_SIZE + len_round + FASTSEC_TRAILER_SIZE;
        (*read_count) += FASTSEC_HEADER_SIZE + len_round + FASTSEC_TRAILER_SIZE;
        datalen -= FASTSEC_HEADER_SIZE + len_round + FASTSEC_TRAILER_SIZE;
    }
    return FASTSEC_RESULT_AVAIL_SUCCESS;
}


enum fastsec_housekeeping_result fastsec_housekeeping (struct fastsec *fs, char *buf, int buflen, int *result_len)
{
    time_t now;
    const int maxlen = FASTSEC_HEADER_SIZE + 23 + FASTSEC_BLOCK_SZ + FASTSEC_TRAILER_SIZE + FASTSEC_HEADER_SIZE + 0 + FASTSEC_BLOCK_SZ + FASTSEC_TRAILER_SIZE;

    *result_len = 0;

    if (buflen < maxlen)
        return FASTSEC_HOUSEKEEPING_RESULT_FAIL_BUF_TOO_SMALL;

    time (&now);

    buf[maxlen - 1] = '~';

    if (!*fs->future_packet_sent) {
        *fs->future_packet_sent = 1;
        memset (&buf[FASTSEC_HEADER_SIZE], '\0', 23);
/* verify that future packet-types don't terminate the remote end */
        *result_len += fastsec_encrypt_packet (&buf[*result_len], &fs->non_replay_counter_encrypt, &fs->aes_encrypt, fs->randseries, FASTSEC_PKTTYPE_FUTURE, 23);
    }

    if (!*fs->last_hb_sent || now > *fs->last_hb_sent) {
        *fs->last_hb_sent = now;
        *result_len += fastsec_encrypt_packet (&buf[*result_len], &fs->non_replay_counter_encrypt, &fs->aes_encrypt, fs->randseries, FASTSEC_PKTTYPE_HEARTBEAT, 0);
    }

    assert (buf[maxlen - 1] == '~');

    if (*fs->last_hb_recv && now > *fs->last_hb_recv + 3)
        return FASTSEC_HOUSEKEEPING_RESULT_FAIL_HEARTBEAT_TIMEOUT;

    return FASTSEC_HOUSEKEEPING_RESULT_SUCCESS;
}



