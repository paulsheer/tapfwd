
struct randseries;
struct fastsec;
struct fastsec_action;

enum fastsec_mode {
    FASTSEC_MODE_CLIENT = 0,
    FASTSEC_MODE_SERVER = 1
};

enum fastsec_auth {
    FASTSEC_MODE_AUTH_ALLOW_UNKNOWN_PEERS = 0,
    FASTSEC_MODE_AUTH_REJECT_UNKNOWN_PEERS = 1,
};


enum fastsec_result_keyexchange {
    FASTSEC_RESULT_KEYEXCHANGE_SUCCESS = 0,
    FASTSEC_RESULT_KEYEXCHANGE_ACTION_TIMEOUT = 10,
    FASTSEC_RESULT_KEYEXCHANGE_STORAGE_ERROR = 20,
    FASTSEC_RESULT_KEYEXCHANGE_SECURITY_ERROR = 30,
    FASTSEC_RESULT_KEYEXCHANGE_ACTION = 40,
    FASTSEC_RESULT_KEYEXCHANGE_FAIL_NAME_VALIDATION = 50,
};

enum fastsec_result_decrypt {
    FASTSEC_RESULT_DECRYPT_SUCCESS = 0,
    FASTSEC_RESULT_DECRYPT_FAIL_PKTTYPE = 110,
    FASTSEC_RESULT_DECRYPT_FAIL_LEN = 120,
    FASTSEC_RESULT_DECRYPT_FAIL_CHKSUM = 130,
    FASTSEC_RESULT_DECRYPT_FAIL_REPLAY = 140,
};

enum fastsec_result_process_ciphertext {
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_SUCCESS = 0,
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_AGAIN = 210,
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_ACTION = 220,
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_LENGTH_TOO_LARGE = 230,
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_DECRYPT = 240,
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_CLIENTCLOSERESPONSE_INVALID_PKT_SIZE = 250,
    FASTSEC_RESULT_PROCESS_CIPHERTEXT_FAIL_CLIENT_RCVD_CLIENTCLOSEREQ = 260,
};

enum fastsec_result_housekeeping {
    FASTSEC_RESULT_HOUSEKEEPING_SUCCESS = 0,
    FASTSEC_RESULT_HOUSEKEEPING_FAIL_HEARTBEAT_TIMEOUT = 310,
    FASTSEC_RESULT_HOUSEKEEPING_FAIL_BUF_TOO_SMALL = 320,
    FASTSEC_RESULT_HOUSEKEEPING_AGAIN = 330,
    FASTSEC_RESULT_HOUSEKEEPING_ACTION = 340,
};

enum fastsec_result_init {
    FASTSEC_RESULT_INIT_SUCCESS = 0,
    FASTSEC_RESULT_INIT_FAIL_PRIVKEY = 410,
    FASTSEC_RESULT_INIT_FAIL_REMOTEPUBKEY = 420,
    FASTSEC_RESULT_INIT_FAIL_PUBKEY = 430,
};

enum fastsec_action_type {
    FASTSEC_ACTION_TYPE_RESULT = 1,
    FASTSEC_ACTION_TYPE_OK,
    FASTSEC_ACTION_TYPE_CANCEL,
    FASTSEC_ACTION_TYPE_CIPHERTEXT_AVAIL,
    FASTSEC_ACTION_TYPE_PLAINTEXT_AVAIL,
    FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT,
    FASTSEC_ACTION_TYPE_WANT_CIPHERTEXT_BUF,
    FASTSEC_ACTION_TYPE_CONSUME_CIPHERTEXT_SUCCESS,
};

struct fastsec_action {
    enum fastsec_action_type action;
    char *data;
    int datalen;
    int result;
};

#define FASTSEC_CLIENTNAME_MAXLEN               96
#define FASTSEC_BLOCK_SZ                        16
#define FASTSEC_KEY_SZ                          32
#define FASTSEC_ERRMSG_LEN                      160
#define FASTSEC_BUF_SIZE                        16384

enum fastsec_packet_type {
    FASTSEC_PKTTYPE_DATA = 1,
    FASTSEC_PKTTYPE_HEARTBEAT = 2,
    FASTSEC_PKTTYPE_CLIENTCLOSEREQ = 3,
    FASTSEC_PKTTYPE_RESPONSETOCLOSEREQ = 4,
    FASTSEC_PKTTYPE_FUTURE = 255,       /* verify that future packet-types don't terminate the remote end. */
};

extern int _fastsec_header_size;
extern int _fastsec_trailer_size;

#define FASTSEC_FULLLEN(c)      ((c) + (int) sizeof(struct pkthdr_chk))
#define FASTSEC_CRYPTLEN(c)     ((FASTSEC_FULLLEN(c) + (FASTSEC_BLOCK_SZ - 1)) - ((FASTSEC_FULLLEN(c) + (FASTSEC_BLOCK_SZ - 1))) % FASTSEC_BLOCK_SZ)
#define FASTSEC_ROUND(c)        (FASTSEC_CRYPTLEN(c) - (int) sizeof(struct pkthdr_chk))

struct fastsec_stats {
    uint64_t pkt_recv_count;
    uint64_t pkt_send_count;
};

struct fastsec;
struct reconnect_ticket;
struct symauth;

enum fastsec_result_process_ciphertext fastsec_process_ciphertext (struct fastsec *fs, struct fastsec_action *fsa, enum fastsec_result_decrypt *err_decrypt);
enum fastsec_result_housekeeping fastsec_housekeeping (struct fastsec *fs, struct fastsec_action *fsa);
int fastsec_connected (struct fastsec *fs);
int fastsec_got_close_request (struct fastsec *fs);
enum fastsec_result_keyexchange fastsec_keyexchange (struct fastsec *fs, struct fastsec_action *a, char *errmsg);
void _fastsec_runcurvetests (void);
int fastsec_retrievepubkey (struct fastsec *fs, char *out, int outlen, char *errmsg);
int fastsec_validateclientname (const char *clientname);
void _fastsec_aesoneblock (const unsigned char *key, int key_len, const unsigned char *in, unsigned char *out);
void fastsec_set_mode (struct fastsec *fs, enum fastsec_mode m);
void fastsec_set_no_store (struct fastsec *fs, int nostore);
void fastsec_set_auth_names (struct fastsec *fs, const char *clientname, const char *remotename);
void fastsec_set_strict_auth (struct fastsec *fs, enum fastsec_auth auth);
void fastsec_construct_ticket (struct fastsec *fs, struct reconnect_ticket *ticket);
enum fastsec_result_decrypt _fastsec_decrypt_packet (char *in, int len_round, int *pkttype, uint64_t *non_replay_counter, struct symauth *symauth, int *len);
int fastsec_encrypt_packet (struct fastsec *fs, char *const out, int pkttype, const int len);
enum fastsec_result_init fastsec_init (struct fastsec *fs, char *errmsg);
void fastsec_free (struct fastsec *fs);
void fastsec_stats (struct fastsec *fs, struct fastsec_stats *);
struct fastsec *fastsec_new (void);
void fastsec_reconnect (struct fastsec *fs);
int fastsec_header_size (struct fastsec *fs);
int fastsec_trailer_size (struct fastsec *fs);
void fastsec_set_verbose (struct fastsec *fs, int verbose);










