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


struct fastsec {
    int server_mode;
    int connected;
    union fastsec_frame frame;
    struct fastsec_stats stats;
    uint64_t non_replay_counter_encrypt;
    uint64_t non_replay_counter_decrypt;
    struct randseries *randseries;
    struct aes_key_st aes_encrypt;
    struct aes_key_st aes_decrypt;
    time_t last_hb_sent;
    time_t last_hb_recv;
    union reconnect_ticket *save_ticket;
    int server_ticket_recieved;
    int client_close_req_recieved;
    int future_packet_sent;
    int fd_remotepubkey;
    int fd_privkey;
    int fd_pubkey;
    int auth_mode;
    int no_store;
    const char *remotepubkey_fname;
    const char *pubkey_fname;
    const char *privkey_fname;
    const char *clientname;
    const char *remotename;
    union reconnect_ticket *reconnect_ticket;
};




static int fastsec_has_hw_aes = 0;


/* y² = x³ + 486662x² + x */
extern int curve25519 (unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

/* y² + x² = 1 − 39081x²y² */
extern int curve448 (unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);



#define CURVE_KEYLEN_BOTH               (32 + 56)



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
    vsnprintf (errmsg, FASTSEC_ERRMSG_LEN, fmt, ap);
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

static enum fastsec_result_keyexchange store_remote_public_key (int fd, const char *fname, const char *host, struct eckey *pubkey, int no_new_keys, int no_store, char *errmsg)
{
    int line = 0;
    char t[1024];
    struct fdcache cache;
    memset (&cache, '\0', sizeof (cache));
    if (fd_position (fd, fname, 0, errmsg))
        return FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR;
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
            return FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR;
        }
        if (memcmp ((void *) pubkey, pubkeycmp, CURVE_KEYLEN_BOTH)) {
            err_sprintf (errmsg, "error: %s:%d: public key for remote '%s' does not match", fname, line, host);
            return FASTSEC_RESULT_KEYEXCHANGE_SECURITY_ERROR;
        }
        printf ("%s:%d: public key for remote '%s' successfully matched\n", fname, line, host);
        return FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;
    }

    if (no_store) {
        return FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;
    }

    if (no_new_keys) {
        err_sprintf (errmsg, "error: %s:%d: public key for remote '%s' does not exist (see -auth and -noauth options)", fname, line, host);
        return FASTSEC_RESULT_KEYEXCHANGE_SECURITY_ERROR;
    }

    if (fd_position (fd, fname, 1, errmsg))
        return FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR;
    strcpy (t, host);
    strcat (t, "\t");
    write_hex_str (t + strlen (t), (const unsigned char *) pubkey, CURVE_KEYLEN_BOTH);
    strcat (t, "\n");
    printf ("%s:%d: stored new public key for '%s'\n", fname, line, host);
    if ((int) write (fd, t, strlen (t)) != (int) strlen (t)) {
        err_sprintf (errmsg, "%s: writing to key store: %s", fname, strerror (errno));
        return FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR;
    }
    return FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;
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

void _fastsec_runcurvetests (void)
{
    test_curve448 ();
    test_curve25519 ();
}

int fastsec_retrievepubkey (struct fastsec *fs, char *out, int outlen, char *errmsg)
{
    int fd_privkey = -1;
    int fd_pubkey = -1;
    struct eckey pubkey;
    struct eckey privkey;

    memset (out, '\0', outlen);
    if ((fd_privkey = open (fs->privkey_fname, O_RDWR | O_CREAT, 0600)) == -1) {
        /* this means we don't access (not running as root), so we should
         * just read the public key from its file: */
        FILE *f;
        printf ("%s: %s\n", fs->privkey_fname, strerror (errno));
        f = fopen (fs->pubkey_fname, "r");
        if (!f) {
            err_sprintf (errmsg, "%s: %s", fs->pubkey_fname, strerror (errno));
            return 1;
        }
        if (!fgets (out, outlen, f)) {
            err_sprintf (errmsg, "%s: short read", fs->pubkey_fname);
            return 1;
        }
        if (strlen (out) <= CURVE_KEYLEN_BOTH * 2) {
            err_sprintf (errmsg, "%s: short file", fs->pubkey_fname);
            return 1;
        }
    } else {
        struct stat st1, st2;
        memset (&st1, '\0', sizeof (st1));
        memset (&st2, '\0', sizeof (st2));
        if (fstat (fd_privkey, &st1)) {
            err_sprintf (errmsg, "%s: %s", fs->privkey_fname, strerror (errno));
            return 1;
        }
        if (!stat (fs->pubkey_fname, &st2)) {
            if (st1.st_uid != st2.st_uid) {
                err_sprintf (errmsg, "%s and %s have different ownership", fs->privkey_fname, fs->pubkey_fname);
                return 1;
            }
        }
        if ((fd_pubkey = open (fs->pubkey_fname, O_RDWR | O_CREAT, 0644)) == -1) {
            err_sprintf (errmsg, "%s: %s", fs->pubkey_fname, strerror (errno));
            return 1;
        }
        if (make_public_private_key (fd_privkey, fs->privkey_fname, fd_pubkey, fs->pubkey_fname, fs->randseries, &privkey, &pubkey, errmsg))
            return 1;
        write_hex_str (out, (const unsigned char *) &pubkey, CURVE_KEYLEN_BOTH);
    }
    return 0;
}

void _fastsec_aesoneblock (const unsigned char *key, int key_len, const unsigned char *in, unsigned char *out)
{
    struct aes_key_st aes;
    if (aes_set_encrypt_key (key, key_len * 8, &aes)) {
        fprintf (stderr, "error: failure setting key\n");
        exit (1);
    }
    aes_encrypt (in, out, &aes);
    memset (&aes, '\0', sizeof (aes));
}

static void keydgst (const unsigned char *egg_white, const unsigned char *egg_yolk, unsigned char *out)
{
    if (FASTSEC_KEY_SZ == 16) {
/* for backward compatibility with a previous version: */
        _fastsec_aesoneblock (egg_yolk, 16, egg_white, out);
    } else {
        memcpy (out, egg_white, FASTSEC_KEY_SZ);
        _fastsec_aesoneblock (egg_white, FASTSEC_KEY_SZ, egg_yolk, out);
    }
}

enum fastsec_result_init fastsec_init (struct fastsec *fs, char *errmsg)
{
    const char *privkey_fname = "/var/tmp/tapfwd-ecurve-private-key.dat";
    const char *remotepubkey_fname = "/var/tmp/tapfwd-ecurve-remote-public-key.dat";
    const char *pubkey_fname = "/var/tmp/tapfwd-ecurve-public-key.dat";

    _fastsec_runcurvetests ();

    fs->remotepubkey_fname = remotepubkey_fname;
    fs->pubkey_fname = pubkey_fname;
    fs->privkey_fname = privkey_fname;

    assert (fs->server_mode == -1);
    assert (fs->fd_privkey == -1);
    assert (fs->fd_remotepubkey == -1);
    assert (fs->fd_pubkey == -1);

    if ((fs->fd_privkey = open (fs->privkey_fname, O_RDWR | O_CREAT, 0600)) == -1) {
        err_sprintf (errmsg, "error opening %s", fs->privkey_fname);
        return FASTSEC_RESULT_INIT_FAIL_PRIVKEY;
    }
    if ((fs->fd_remotepubkey = open (fs->remotepubkey_fname, O_RDWR | O_CREAT, 0644)) == -1) {
        err_sprintf (errmsg, "error opening %s", fs->remotepubkey_fname);
        return FASTSEC_RESULT_INIT_FAIL_REMOTEPUBKEY;
    }
    if ((fs->fd_pubkey = open (fs->pubkey_fname, O_RDWR | O_CREAT, 0644)) == -1) {
        err_sprintf (errmsg, "error opening %s", fs->pubkey_fname);
        return FASTSEC_RESULT_INIT_FAIL_PUBKEY;
    }

    if (FASTSEC_KEY_SZ == 32)
        fastsec_has_hw_aes = aes_has_aesni ();
    else
        fastsec_has_hw_aes = 0;

    fs->randseries = randseries_new (FASTSEC_KEY_SZ);

    return FASTSEC_RESULT_INIT_SUCCESS;
}

struct fastsec *fastsec_new (void)
{
    struct fastsec *fs;
    fs = malloc (sizeof (*fs));
    memset (fs, '\0', sizeof (*fs));
    fs->server_mode = -1;
    fs->fd_privkey = -1;
    fs->fd_remotepubkey = -1;
    fs->fd_pubkey = -1;
    return fs;
}

void fastsec_free (struct fastsec *fs)
{
    if (fs->fd_privkey >= 0)
        close (fs->fd_privkey);
    if (fs->fd_remotepubkey >= 0)
        close (fs->fd_remotepubkey);
    if (fs->fd_pubkey >= 0)
        close (fs->fd_pubkey);
    memset (fs, '\0', sizeof (*fs));
    free (fs);
}

void fastsec_reconnect (struct fastsec *fs)
{
    fs->frame.state = FASTSEC_STATE_IDLE;
    fs->connected = 0;
    fs->client_close_req_recieved = 0;
    fs->future_packet_sent = 0;
    fs->last_hb_recv = 0L;
    fs->last_hb_sent = 0L;
    memset (&fs->stats, '\0', sizeof (fs->stats));
    fs->non_replay_counter_encrypt = fs->non_replay_counter_decrypt = 0x5555555555555555ULL;
}

void fastsec_set_mode (struct fastsec *fs, enum fastsec_mode m)
{
    assert (fs->server_mode == -1 && "fastsec_set_mode can be called only once");
    assert (m == FASTSEC_MODE_CLIENT || m == FASTSEC_MODE_SERVER);
    fs->server_mode = (m == FASTSEC_MODE_SERVER);
    if (fs->server_mode)
        fs->auth_mode = 1;
}

void fastsec_set_auth_names (struct fastsec *fs, const char *clientname, const char *remotename)
{
    assert (fs->server_mode == FASTSEC_MODE_CLIENT && "fastsec_set_auth_names called as server");
    fs->clientname = clientname;
    fs->remotename = remotename;
}

void fastsec_set_no_store (struct fastsec *fs, int nostore)
{
    assert (fs->server_mode != -1 && "fastsec_set_mode has not been called");
    fs->no_store = nostore;
}

void fastsec_set_strict_auth (struct fastsec *fs, enum fastsec_auth auth)
{
    assert (fs->server_mode != -1 && "fastsec_set_mode must be called before fastsec_set_strict_auth");
    assert (auth == FASTSEC_MODE_AUTH_REJECT_UNKNOWN_PEERS || auth == FASTSEC_MODE_AUTH_ALLOW_UNKNOWN_PEERS);
    fs->auth_mode = (auth == FASTSEC_MODE_AUTH_REJECT_UNKNOWN_PEERS);
}

int fastsec_got_close_request (struct fastsec *fs)
{
    return fs->client_close_req_recieved;
}

static int fastsec_set_aeskeys (unsigned char *key1, struct aes_key_st *aes1, unsigned char *key2, struct aes_key_st *aes2)
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

enum fastsec_result_keyexchange fastsec_keyexchange (struct fastsec *fs, struct fastsec_action *a, char *errmsg)
{

#define FRAME_state fs->frame.fastsec_keyexchange.state
#define FRAME_start_time fs->frame.fastsec_keyexchange.start_time
#define FRAME_hd fs->frame.fastsec_keyexchange.hd
#define FRAME_aes_key_encrypt fs->frame.fastsec_keyexchange.aes_key_encrypt
#define FRAME_aes_key_decrypt fs->frame.fastsec_keyexchange.aes_key_decrypt

    enum fastsec_result_keyexchange r = FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;

/* for backward compatibility with a previous version: */
#define JUSTIFY(l,b)    (((l) - (b)) < (b) ? ((l) - (b)) : (b))
#define LEFT(a,b)       &a[0]
#define RGHT(a,b)       &a[JUSTIFY(sizeof(a),b)]

    assert (!fs->connected && fs->frame.state != FASTSEC_STATE_CONNECTED && "user called fastsec_keyexchange in connected state");

    if (FRAME_state == FASTSEC_STATE_KEYEXCHANGE_IDLE) {
        memset (&fs->frame.fastsec_keyexchange, '\0', sizeof (fs->frame.fastsec_keyexchange));
        time (&FRAME_start_time);
    } else {
        time_t now;
        time (&now);
        if (now > FRAME_start_time + 10)
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION_TIMEOUT;
    }

    if (fs->server_mode) {

        switch (FRAME_state) {

        case FASTSEC_STATE_KEYEXCHANGE_CONNECTED:
            assert (!"not reached");
            break;

        case FASTSEC_STATE_KEYEXCHANGE_IDLE:
            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_WANT_CIPHERTEXT;

            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT;
            a->result = sizeof (FRAME_hd.ch);
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_WANT_CIPHERTEXT:

            if (a->datalen < (int) sizeof (FRAME_hd.ch)) {
                FRAME_state = FASTSEC_STATE_KEYEXCHANGE_WANT_CIPHERTEXT;
                memset (a, '\0', sizeof (*a));
                a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT;
                a->result = sizeof (FRAME_hd.ch);
                return FASTSEC_RESULT_KEYEXCHANGE_ACTION;
            }

            assert (a->data);
            memcpy (&FRAME_hd.ch, a->data, sizeof (FRAME_hd.ch));

            a->action = FASTSEC_ACTION_TYPE_CONSUME_CIPHERTEXT_SUCCESS;
            a->result = (int) sizeof (FRAME_hd.ch);
            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP1;
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP1:

            FRAME_hd.ch.clientname[FASTSEC_CLIENTNAME_MAXLEN - 1] = '\0';
            if (fastsec_validateclientname (FRAME_hd.ch.clientname))
                return FASTSEC_RESULT_KEYEXCHANGE_FAIL_NAME_VALIDATION;
            if ((r = store_remote_public_key (fs->fd_remotepubkey, fs->remotepubkey_fname, FRAME_hd.ch.clientname, &FRAME_hd.ch.pubkey, fs->auth_mode, fs->no_store, errmsg)) != FASTSEC_RESULT_KEYEXCHANGE_SUCCESS)
                return r;
            printf ("received client hello\n");
            if (make_public_private_key (fs->fd_privkey, fs->privkey_fname, fs->fd_pubkey, fs->pubkey_fname, fs->randseries, &FRAME_hd.privkey, &FRAME_hd.sh.pubkey, errmsg))
                return FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR;
            make_transient_public_private_key (fs->randseries, &FRAME_hd.transient_privkey, &FRAME_hd.sh.transient_pubkey);

            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP2;
            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF;
            a->result = sizeof (FRAME_hd.sh);

            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP2:
            if (a->datalen < (int) sizeof (FRAME_hd.sh)) {
                FRAME_state = FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP2;
                memset (a, '\0', sizeof (*a));
                a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF;
                a->result = sizeof (FRAME_hd.sh);
                return FASTSEC_RESULT_KEYEXCHANGE_ACTION;
            }

            memcpy (a->data, &FRAME_hd.sh, sizeof (FRAME_hd.sh));

            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_CIPHERTEXT_AVAIL;
            a->result = sizeof (FRAME_hd.sh);
            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_DO_MATH;
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_DO_MATH:

            printf ("sent server hello\n");
            curve25519 (FRAME_hd.shared_secret.v25519, FRAME_hd.privkey.v25519, FRAME_hd.ch.pubkey.v25519);
            curve448 (FRAME_hd.shared_secret.v448, FRAME_hd.privkey.v448, FRAME_hd.ch.pubkey.v448);
            curve25519 (FRAME_hd.trnsnt_secret.v25519, FRAME_hd.transient_privkey.v25519, FRAME_hd.ch.transient_pubkey.v25519);
            curve448 (FRAME_hd.trnsnt_secret.v448, FRAME_hd.transient_privkey.v448, FRAME_hd.ch.transient_pubkey.v448);
            keydgst (LEFT (FRAME_hd.shared_secret.v448, FASTSEC_KEY_SZ), LEFT (FRAME_hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_aes_key_encrypt);
            keydgst (RGHT (FRAME_hd.shared_secret.v448, FASTSEC_KEY_SZ), RGHT (FRAME_hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_aes_key_decrypt);
            keydgst (LEFT (FRAME_hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), LEFT (FRAME_hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_hd.transient_key1);
            keydgst (RGHT (FRAME_hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), RGHT (FRAME_hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_hd.transient_key2);
            xor_mem (FRAME_aes_key_encrypt, FRAME_hd.transient_key1, FASTSEC_KEY_SZ);
            xor_mem (FRAME_aes_key_decrypt, FRAME_hd.transient_key2, FASTSEC_KEY_SZ);

            if (fastsec_set_aeskeys (FRAME_aes_key_encrypt, &fs->aes_encrypt, FRAME_aes_key_decrypt, &fs->aes_decrypt)) {
                assert (!"failure setting key");
            }

            /* hide secrets: */
            memset (&fs->frame.fastsec_keyexchange, '\0', sizeof (fs->frame.fastsec_keyexchange));
            fs->frame.state = FASTSEC_STATE_CONNECTED;
            fs->connected = 1;
            return FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;
        }

    } else {

        switch (FRAME_state) {

        case FASTSEC_STATE_KEYEXCHANGE_CONNECTED:
            assert (!"not reached");
            break;

        case FASTSEC_STATE_KEYEXCHANGE_IDLE:
            if (make_public_private_key (fs->fd_privkey, fs->privkey_fname, fs->fd_pubkey, fs->pubkey_fname, fs->randseries, &FRAME_hd.privkey, &FRAME_hd.ch.pubkey, errmsg))
                return FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR;
            make_transient_public_private_key (fs->randseries, &FRAME_hd.transient_privkey, &FRAME_hd.ch.transient_pubkey);
            strcpy (FRAME_hd.ch.clientname, fs->clientname);

            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP1;
            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF;
            a->result = sizeof (FRAME_hd.ch);
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP1:
            if (a->datalen < (int) sizeof (FRAME_hd.ch)) {
                FRAME_state = FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP1;
                memset (a, '\0', sizeof (*a));
                a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF;
                a->result = sizeof (FRAME_hd.ch);
                return FASTSEC_RESULT_KEYEXCHANGE_ACTION;
            }

            memcpy (a->data, &FRAME_hd.ch, sizeof (FRAME_hd.ch));

            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_CIPHERTEXT_AVAIL;
            a->result = sizeof (FRAME_hd.ch);
            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP2;
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_MIDDLE_STEP2:

            printf ("sent client hello, %d bytes\n", (int) sizeof (FRAME_hd.ch));

            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_WANT_CIPHERTEXT;
            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT;
            a->result = sizeof (FRAME_hd.sh);
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_WANT_CIPHERTEXT:

            if (a->datalen < (int) sizeof (FRAME_hd.sh)) {
                FRAME_state = FASTSEC_STATE_KEYEXCHANGE_WANT_CIPHERTEXT;
                memset (a, '\0', sizeof (*a));
                a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT;
                a->result = sizeof (FRAME_hd.sh);
                return FASTSEC_RESULT_KEYEXCHANGE_ACTION;
            }

            assert (a->data && "fastsec_action data member NULL after WANT_CIPHERTEXT request");
            memcpy (&FRAME_hd.sh, a->data, sizeof (FRAME_hd.sh));

            a->action = FASTSEC_ACTION_TYPE_CONSUME_CIPHERTEXT_SUCCESS;
            a->result = (int) sizeof (FRAME_hd.sh);
            FRAME_state = FASTSEC_STATE_KEYEXCHANGE_DO_MATH;
            return FASTSEC_RESULT_KEYEXCHANGE_ACTION;

        case FASTSEC_STATE_KEYEXCHANGE_DO_MATH:

            if ((r = store_remote_public_key (fs->fd_remotepubkey, fs->remotepubkey_fname, fs->remotename, &FRAME_hd.sh.pubkey, fs->auth_mode, 0, errmsg)) != FASTSEC_RESULT_KEYEXCHANGE_SUCCESS)
                return r;
            printf ("received server hello\n");
            curve25519 (FRAME_hd.shared_secret.v25519, FRAME_hd.privkey.v25519, FRAME_hd.sh.pubkey.v25519);
            curve448 (FRAME_hd.shared_secret.v448, FRAME_hd.privkey.v448, FRAME_hd.sh.pubkey.v448);
            curve25519 (FRAME_hd.trnsnt_secret.v25519, FRAME_hd.transient_privkey.v25519, FRAME_hd.sh.transient_pubkey.v25519);
            curve448 (FRAME_hd.trnsnt_secret.v448, FRAME_hd.transient_privkey.v448, FRAME_hd.sh.transient_pubkey.v448);
            keydgst (LEFT (FRAME_hd.shared_secret.v448, FASTSEC_KEY_SZ), LEFT (FRAME_hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_aes_key_decrypt);
            keydgst (RGHT (FRAME_hd.shared_secret.v448, FASTSEC_KEY_SZ), RGHT (FRAME_hd.shared_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_aes_key_encrypt);
            keydgst (LEFT (FRAME_hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), LEFT (FRAME_hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_hd.transient_key2);
            keydgst (RGHT (FRAME_hd.trnsnt_secret.v448, FASTSEC_KEY_SZ), RGHT (FRAME_hd.trnsnt_secret.v25519, FASTSEC_BLOCK_SZ), FRAME_hd.transient_key1);
            xor_mem (FRAME_aes_key_decrypt, FRAME_hd.transient_key2, FASTSEC_KEY_SZ);
            xor_mem (FRAME_aes_key_encrypt, FRAME_hd.transient_key1, FASTSEC_KEY_SZ);

            if (fastsec_set_aeskeys (FRAME_aes_key_encrypt, &fs->aes_encrypt, FRAME_aes_key_decrypt, &fs->aes_decrypt)) {
                assert (!"failure setting key");
            }

            /* hide secrets: */
            memset (&fs->frame.fastsec_keyexchange, '\0', sizeof (fs->frame.fastsec_keyexchange));
            fs->frame.state = FASTSEC_STATE_CONNECTED;
            fs->connected = 1;
            return FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;
        }
    }

    assert (!"not reached");
    return FASTSEC_RESULT_KEYEXCHANGE_SUCCESS;

#undef FRAME_state
#undef FRAME_start_time
#undef FRAME_hd
#undef FRAME_aes_key_encrypt
#undef FRAME_aes_key_decrypt

}


int fastsec_encrypt_packet (struct fastsec *fs, char *out, int pkttype, int len)
{
    struct header *h;
    struct trailer *t;
    unsigned char iv[FASTSEC_BLOCK_SZ];

    h = (struct header *) out;

    write_uint (&h->hdr.pkttype, pkttype, sizeof (h->hdr.pkttype));
    write_uint (&h->hdr.length, FASTSEC_ROUND (len), sizeof (h->hdr.length));
    write_uint (&h->hdr_chk.non_replay_counter, fs->non_replay_counter_encrypt, sizeof (h->hdr_chk.non_replay_counter));
    write_uint (&h->hdr_chk.pkttype, pkttype, sizeof (h->hdr_chk.pkttype));
    write_uint (&h->hdr_chk.length, len, sizeof (h->hdr_chk.length));

    fs->non_replay_counter_encrypt++;

    randseries_bytes (fs->randseries, iv, FASTSEC_BLOCK_SZ);
    memcpy (h->iv, iv, FASTSEC_BLOCK_SZ);

    /* zero trailing bytes */
    memset (((unsigned char *) &h->hdr_chk) + FASTSEC_FULLLEN (len), '\0', FASTSEC_CRYPTLEN (len) - FASTSEC_FULLLEN (len));

    if (fastsec_has_hw_aes)
        aes_ni_cbc_encrypt ((const unsigned char *) &h->hdr_chk, (unsigned char *) &h->hdr_chk, FASTSEC_CRYPTLEN (len), &fs->aes_encrypt, iv);
    else
        aes_cbc128_encrypt ((const unsigned char *) &h->hdr_chk, (unsigned char *) &h->hdr_chk, FASTSEC_CRYPTLEN (len), &fs->aes_encrypt, iv);

    t = (struct trailer *) &out[FASTSEC_HEADER_SIZE + FASTSEC_ROUND (len)];
    memcpy (t->chksum, iv, FASTSEC_BLOCK_SZ);

    fs->stats.pkt_send_count++;

    return FASTSEC_HEADER_SIZE + FASTSEC_ROUND (len) + FASTSEC_TRAILER_SIZE;
}


enum fastsec_result_decrypt _fastsec_decrypt_packet (char *in, int len_round, int *pkttype, uint64_t *non_replay_counter, struct aes_key_st *aes, int *len)
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


void fastsec_stats (struct fastsec *fs, struct fastsec_stats *s)
{
    *s = fs->stats;
}


int fastsec_connected (struct fastsec *fs)
{
    return fs->connected;
}



enum fastsec_result_process_ciphertext fastsec_process_ciphertext (struct fastsec *fs, struct fastsec_action *a, enum fastsec_result_decrypt *err_decrypt)
{

#define FRAME_state fs->frame.fastsec_process_ciphertext.state
#define FRAME_data fs->frame.fastsec_process_ciphertext.data
#define FRAME_datalen fs->frame.fastsec_process_ciphertext.datalen
#define FRAME_now fs->frame.fastsec_process_ciphertext.now
#define FRAME_readcount fs->frame.fastsec_process_ciphertext.readcount
#define FRAME_len fs->frame.fastsec_process_ciphertext.len
#define FRAME_lenround fs->frame.fastsec_process_ciphertext.lenround
#define FRAME_pkttype fs->frame.fastsec_process_ciphertext.pkttype

    switch (FRAME_state) {

    case FASTSEC_STATE_PROCESS_CIPHERTEXT_CONNECTED:
        memset (&fs->frame.fastsec_process_ciphertext, '\0', sizeof (fs->frame.fastsec_process_ciphertext));
        FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_WANT_CIPHERTEXT;
        memset (a, '\0', sizeof (*a));
        a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT;
        return FASTSEC_RESULT_PROCESS_CIPHERTEXT_ACTION;

    case FASTSEC_STATE_PROCESS_CIPHERTEXT_WANT_CIPHERTEXT:
        assert (a->action == FASTSEC_ACTION_TYPE_OK);
        FRAME_data = a->data;
        FRAME_datalen = a->datalen;
        FRAME_readcount = 0;
        time (&FRAME_now);
        FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_DECRYPTING;
        /* fallthrough */

    case FASTSEC_STATE_PROCESS_CIPHERTEXT_DECRYPTING:
        assert (FRAME_data);

        if (FRAME_datalen < FASTSEC_HEADER_SIZE)
            goto done;

        {
            struct header *h;
            h = (struct header *) FRAME_data;
            FRAME_lenround = read_uint (&h->hdr.length, sizeof (h->hdr.length));
        }

        if (FRAME_lenround > FASTSEC_BUF_SIZE - (FASTSEC_HEADER_SIZE + FASTSEC_ROUND (0) + FASTSEC_TRAILER_SIZE)) {
            FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_CONNECTED;
            return FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_LENGTH_TOO_LARGE;
        }

        if (FRAME_datalen < FASTSEC_HEADER_SIZE + FRAME_lenround + FASTSEC_TRAILER_SIZE)
            goto done;

        {
            enum fastsec_result_decrypt err;
            switch ((err = _fastsec_decrypt_packet (FRAME_data, FRAME_lenround, &FRAME_pkttype, &fs->non_replay_counter_decrypt, &fs->aes_decrypt, &FRAME_len))) {
            case FASTSEC_RESULT_DECRYPT_SUCCESS:
                break;
            default:
                *err_decrypt = err;
                FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_CONNECTED;
                return FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_DECRYPT;
            }
        }

        fs->stats.pkt_recv_count++;

        switch (FRAME_pkttype) {
        case FASTSEC_PKTTYPE_DATA:
            memset (a, '\0', sizeof (*a));
            a->action = FASTSEC_ACTION_TYPE_PLAINTEXT_AVAIL;
            a->data = (FRAME_data + FASTSEC_HEADER_SIZE);
            a->datalen = FRAME_len;
            FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_DECRYPTING_NEXT;
            return FASTSEC_RESULT_PROCESS_CIPHERTEXT_ACTION;

        case FASTSEC_PKTTYPE_HEARTBEAT:
            fs->last_hb_recv = FRAME_now;
            break;

        case FASTSEC_PKTTYPE_RESPONSETOCLOSEREQ:
            if (FRAME_len != sizeof (*fs->save_ticket)) {
                FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_CONNECTED;
                return FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_CLIENTCLOSERESPONSE_INVALID_PKT_SIZE;
            }
            fs->server_ticket_recieved = 1;
            memcpy (fs->save_ticket, FRAME_data + FASTSEC_HEADER_SIZE, sizeof (*fs->save_ticket));
            fs->save_ticket->d.utc_seconds = read_uint (&fs->save_ticket->d.utc_seconds, sizeof (fs->save_ticket->d.utc_seconds));
printf ("TBD\n");
            goto done;

        case FASTSEC_PKTTYPE_CLIENTCLOSEREQ:
            if (fs->server_mode) {
                union reconnect_ticket ticket;
                fs->client_close_req_recieved = 1;
                fastsec_construct_ticket (&ticket);
                memcpy (FRAME_data + FASTSEC_HEADER_SIZE, &ticket, sizeof (ticket));
printf ("TBD\n");
//                 make_encrypted_packet (&buf1, randseries, FASTSEC_PKTTYPE_RESPONSETOCLOSEREQ, FASTSEC_BLOCK_SZ);
            } else {
                FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_CONNECTED;
                return FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_CLIENT_RCVD_CLIENTCLOSEREQ;
            }
            break;

        default:
            /* ignore unknown packet types for future versions */
            break;
        }
        FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_DECRYPTING_NEXT;
        /* fallthrough */

    case FASTSEC_STATE_PROCESS_CIPHERTEXT_DECRYPTING_NEXT:

        FRAME_data += FASTSEC_HEADER_SIZE + FRAME_lenround + FASTSEC_TRAILER_SIZE;
        FRAME_readcount += FASTSEC_HEADER_SIZE + FRAME_lenround + FASTSEC_TRAILER_SIZE;
        FRAME_datalen -= FASTSEC_HEADER_SIZE + FRAME_lenround + FASTSEC_TRAILER_SIZE;

        assert (FRAME_datalen >= 0);
        if (FRAME_datalen > 0) {
            FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_DECRYPTING;
            return FASTSEC_RESULT_PROCESS_CIPHERTEXT_AGAIN;
        }
        goto done;

    }

  done:
    FRAME_state = FASTSEC_STATE_PROCESS_CIPHERTEXT_CONNECTED;
    memset (a, '\0', sizeof (*a));
    a->action = FASTSEC_ACTION_TYPE_RESULT;
    a->result = FRAME_readcount;
    return FASTSEC_RESULT_PROCESS_CIPHERTEXT_SUCCESS;

#undef FRAME_state
#undef FRAME_data
#undef FRAME_datalen
#undef FRAME_now
#undef FRAME_readcount
#undef FRAME_len
#undef FRAME_lenround
#undef FRAME_pkttype

}



enum fastsec_result_housekeeping fastsec_housekeeping (struct fastsec *fs, struct fastsec_action *a)
{

#define FRAME_state fs->frame.fastsec_housekeeping.state
#define FRAME_maxlen fs->frame.fastsec_housekeeping.maxlen
#define FRAME_now fs->frame.fastsec_housekeeping.now

    switch (FRAME_state) {

    case FASTSEC_STATE_HOUSEKEEPING_CONNECTED:
        memset (&fs->frame.fastsec_housekeeping, '\0', sizeof (fs->frame.fastsec_housekeeping));
        time (&FRAME_now);

        if (fs->last_hb_recv && FRAME_now > fs->last_hb_recv + 3) {
            FRAME_state = FASTSEC_STATE_HOUSEKEEPING_CONNECTED;
            return FASTSEC_RESULT_HOUSEKEEPING_FAIL_HEARTBEAT_TIMEOUT;
        }

        if (!fs->future_packet_sent) {
            FRAME_maxlen = FASTSEC_HEADER_SIZE + FASTSEC_ROUND (23) + FASTSEC_TRAILER_SIZE + 1;
            a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF;
            a->result = FRAME_maxlen;
            FRAME_state = FASTSEC_STATE_HOUSEKEEPING_WAITING_BUF_FUTURE_PACKET;
            return FASTSEC_RESULT_HOUSEKEEPING_ACTION;
        }
        FRAME_state = FASTSEC_STATE_HOUSEKEEPING_REQUEST_BUF_HEARTBEAT;
        return FASTSEC_RESULT_HOUSEKEEPING_AGAIN;

    case FASTSEC_STATE_HOUSEKEEPING_WAITING_BUF_FUTURE_PACKET:
        if (a->action == FASTSEC_ACTION_TYPE_CANCEL)
            goto done;
        assert (a->action == FASTSEC_ACTION_TYPE_OK);
        if (a->datalen < FRAME_maxlen) {
            FRAME_state = FASTSEC_STATE_HOUSEKEEPING_CONNECTED;
            return FASTSEC_RESULT_HOUSEKEEPING_FAIL_BUF_TOO_SMALL;
        }

        a->data[FRAME_maxlen - 1] = '~';
        fs->future_packet_sent = 1;
        memset (&a->data[FASTSEC_HEADER_SIZE], '\0', 23);
        a->action = FASTSEC_ACTION_TYPE_CIPHERTEXT_AVAIL;
        a->result = fastsec_encrypt_packet (fs, a->data, FASTSEC_PKTTYPE_FUTURE, 23);
        assert (a->data[FRAME_maxlen - 1] == '~');

        FRAME_state = FASTSEC_STATE_HOUSEKEEPING_REQUEST_BUF_HEARTBEAT;
        return FASTSEC_RESULT_HOUSEKEEPING_ACTION;

    case FASTSEC_STATE_HOUSEKEEPING_REQUEST_BUF_HEARTBEAT:
        if (!fs->last_hb_sent || FRAME_now > fs->last_hb_sent) {
            FRAME_maxlen = FASTSEC_HEADER_SIZE + FASTSEC_ROUND (0) + FASTSEC_TRAILER_SIZE + 1;
            a->action = FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF;
            a->result = FRAME_maxlen;
            FRAME_state = FASTSEC_STATE_HOUSEKEEPING_WAITING_BUF_HEARTBEAT;
            return FASTSEC_RESULT_HOUSEKEEPING_ACTION;
        }
        goto done;

    case FASTSEC_STATE_HOUSEKEEPING_WAITING_BUF_HEARTBEAT:
        if (a->action == FASTSEC_ACTION_TYPE_CANCEL)
            goto done;
        assert (a->action == FASTSEC_ACTION_TYPE_OK);
        if (a->datalen < FRAME_maxlen) {
            FRAME_state = FASTSEC_STATE_HOUSEKEEPING_CONNECTED;
            return FASTSEC_RESULT_HOUSEKEEPING_FAIL_BUF_TOO_SMALL;
        }
        fs->last_hb_sent = FRAME_now;
        a->data[FRAME_maxlen - 1] = '~';
        a->action = FASTSEC_ACTION_TYPE_CIPHERTEXT_AVAIL;
        a->result = fastsec_encrypt_packet (fs, a->data, FASTSEC_PKTTYPE_HEARTBEAT, 0);
        assert (a->data[FRAME_maxlen - 1] == '~');
        FRAME_state = FASTSEC_STATE_HOUSEKEEPING_HOUSEKEEPING_DONE;
        return FASTSEC_RESULT_HOUSEKEEPING_ACTION;

    case FASTSEC_STATE_HOUSEKEEPING_HOUSEKEEPING_DONE:
        goto done;
    }

  done:
    FRAME_state = FASTSEC_STATE_HOUSEKEEPING_CONNECTED;
    memset (a, '\0', sizeof (*a));
    return FASTSEC_RESULT_HOUSEKEEPING_SUCCESS;

#undef FRAME_state
#undef FRAME_maxlen
#undef FRAME_now

}





