
struct randseries;
struct fastsec;

enum fastsec_mode {
    FASTSEC_MODE_CLIENT = 0,
    FASTSEC_MODE_SERVER = 1
};

enum fastsec_auth {
    FASTSEC_MODE_AUTH_ALLOW_UNKNOWN_PEERS = 0,
    FASTSEC_MODE_AUTH_REJECT_UNKNOWN_PEERS = 1,
};

enum fastsec_result {
    FASTSEC_RESULT_SUCCESS = 0,
    FASTSEC_RESULT_STORAGE_ERROR = 10,
    FASTSEC_RESULT_SOCKET_ERROR = 20,
    FASTSEC_RESULT_SECURITY_ERROR = 30,
};

enum fastsec_result_decrypt {
    FASTSEC_RESULT_DECRYPT_SUCCESS = 0,
    FASTSEC_RESULT_DECRYPT_FAIL_PKTTYPE = 110,
    FASTSEC_RESULT_DECRYPT_FAIL_LEN = 120,
    FASTSEC_RESULT_DECRYPT_FAIL_CHKSUM = 130,
    FASTSEC_RESULT_DECRYPT_FAIL_REPLAY = 140,
};

enum fastsec_result_avail {
    FASTSEC_RESULT_AVAIL_SUCCESS = 0,
    FASTSEC_RESULT_AVAIL_SUCCESS_NEED_MORE_INPUT = 210,
    FASTSEC_RESULT_AVAIL_FAIL_LENGTH_TOO_LARGE = 220,
    FASTSEC_RESULT_AVAIL_FAIL_DECRYPT = 230,
    FASTSEC_RESULT_AVAIL_FAIL_PROCESS_PLAINTEXT = 240,
    FASTSEC_RESULT_AVAIL_FAIL_CLIENTCLOSERESPONSE_INVALID_PKT_SIZE = 250,
    FASTSEC_RESULT_AVAIL_FAIL_CLIENT_RCVD_CLIENTCLOSEREQ = 260,
};

enum fastsec_housekeeping_result {
    FASTSEC_HOUSEKEEPING_RESULT_SUCCESS = 0,
    FASTSEC_HOUSEKEEPING_RESULT_FAIL_HEARTBEAT_TIMEOUT = 310,
    FASTSEC_HOUSEKEEPING_RESULT_FAIL_BUF_TOO_SMALL = 320,
};

enum fastsec_init_result {
    FASTSEC_INIT_RESULT_SUCCESS = 0,
    FASTSEC_INIT_RESULT_FAIL_PRIVKEY = 410,
    FASTSEC_INIT_RESULT_FAIL_REMOTEPUBKEY = 420,
    FASTSEC_INIT_RESULT_FAIL_PUBKEY = 430,
};

#define FASTSEC_CLIENTNAME_MAXLEN               96
#define FASTSEC_BLOCK_SZ                        16
#define FASTSEC_KEY_SZ                          32
#define FASTSEC_BUF_SIZE                        16384

enum fastsec_packet_type {
    FASTSEC_PKTTYPE_DATA = 1,
    FASTSEC_PKTTYPE_HEARTBEAT = 2,
    FASTSEC_PKTTYPE_CLIENTCLOSEREQ = 3,
    FASTSEC_PKTTYPE_RESPONSETOCLOSEREQ = 4,
    FASTSEC_PKTTYPE_FUTURE = 255,
};

struct reconnect_ticket_ {
    unsigned char ticket[FASTSEC_BLOCK_SZ];
    uint64_t utc_seconds;
};

union reconnect_ticket {
    struct reconnect_ticket_ d;
    unsigned char blocks[FASTSEC_BLOCK_SZ * 2];
};

enum fastsec_result fastsec_keyexchange (struct fastsec *info, char *errmsg, unsigned char *key1, unsigned char *key2);
void fastsec_runcurvetests (void);
int fastsec_retrievepubkey (struct fastsec *fs, char *out, int outlen, char *errmsg);
int fastsec_validateclientname (const char *clientname);
void fastsec_aesoneblock (const unsigned char *key, int key_len, const unsigned char *in, unsigned char *out);
void fastsec_set_mode (struct fastsec *fs, enum fastsec_mode m);
void fastsec_set_strict_auth (struct fastsec *fs, enum fastsec_auth auth);


void fastsec_construct_ticket (union reconnect_ticket *ticket);

struct pkthdr {
    unsigned char pkttype;
    unsigned short length;
} __attribute ((packed));

struct pkthdr_chk {
    uint64_t non_replay_counter;
    unsigned char pkttype;
    unsigned short length;
} __attribute ((packed));

struct header {
    struct pkthdr hdr;
    unsigned char iv[FASTSEC_BLOCK_SZ];
    struct pkthdr_chk hdr_chk;      /* <== this part is also sent crypto */
} __attribute ((packed));

struct trailer {
    unsigned char chksum[FASTSEC_BLOCK_SZ];
} __attribute ((packed));

#define FASTSEC_HEADER_SIZE     ((int) sizeof(struct header))
#define FASTSEC_TRAILER_SIZE    ((int) sizeof(struct trailer))
#define FASTSEC_FULLLEN(c)      ((c) + (int) sizeof(struct pkthdr_chk))
#define FASTSEC_CRYPTLEN(c)     ((FASTSEC_FULLLEN(c) + (FASTSEC_BLOCK_SZ - 1)) - ((FASTSEC_FULLLEN(c) + (FASTSEC_BLOCK_SZ - 1))) % FASTSEC_BLOCK_SZ)
#define FASTSEC_ROUND(c)        (FASTSEC_CRYPTLEN(c) - (int) sizeof(struct pkthdr_chk))

enum fastsec_result_decrypt fastsec_decrypt_packet (char *in, int len_round, int *pkttype, uint64_t *non_replay_counter, struct aes_key_st *aes, int *len);
int fastsec_encrypt_packet (struct fastsec *fs, char *out, int pkttype, int len);
int fastsec_set_aeskeys (unsigned char *key1, struct aes_key_st *aes1, unsigned char *key2, struct aes_key_st *aes2);
enum fastsec_init_result fastsec_init (struct fastsec *fs);
void fastsec_reconnect (struct fastsec *fs);


typedef int (*fastsec_process_plaintext_cb_t) (void *user_data1, void *user_data2, char *data, int len);

struct fastsec {
    int server_mode;
    fastsec_process_plaintext_cb_t process_plaintext;
    void *user_data1;
    void *user_data2;
    uint64_t pkt_recv_count;
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
    int sock;
    int auth_mode;
    int no_store;
    const char *remotepubkey_fname;
    const char *pubkey_fname;
    const char *privkey_fname;
    const char *clientname;
    const char *remotename;
    union reconnect_ticket *reconnect_ticket;
};

enum fastsec_result_avail fastsec_process_ciphertext (struct fastsec *fs, char *data, int datalen, enum fastsec_result_decrypt *err_decrypt, int *read_count);
enum fastsec_housekeeping_result fastsec_housekeeping (struct fastsec *fs, char *buf, int buflen, int *result_len);











