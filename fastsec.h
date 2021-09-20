
struct randseries;

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

#define FASTSEC_CLIENTNAME_MAXLEN               96
#define FASTSEC_BLOCK_SZ                        16
#define FASTSEC_KEY_SZ                          32

struct fastsec_keyexchange_info {
    int fd_remotepubkey;
    int fd_privkey;
    int fd_pubkey;
    int sock;
    int server_mode;
    int auth_mode;
    int no_store;
    const char *remotepubkey_fname;
    const char *pubkey_fname;
    const char *privkey_fname;
    const char *clientname;
    const char *remotename;
};

enum fastsec_result fastsec_keyexchange (struct fastsec_keyexchange_info *info, struct randseries *randseries, char *errmsg, unsigned char *key1, unsigned char *key2);
void fastsec_runcurvetests (void);
int fastsec_retrievepubkey (const char *privkey_fname, const char *pubkey_fname, struct randseries *randseries, char *out, int outlen, char *errmsg);
int fastsec_validateclientname (const char *clientname);
void fastsec_aesoneblock (const unsigned char *key, int key_len, const unsigned char *in, unsigned char *out);


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
int fastsec_encrypt_packet (char *out, uint64_t *non_replay_counter, struct aes_key_st *aes, struct randseries *s, int pkttype, int len);
int fastsec_set_aeskeys (unsigned char *key1, struct aes_key_st *aes1, unsigned char *key2, struct aes_key_st *aes2);
void fastsec_init (void);







