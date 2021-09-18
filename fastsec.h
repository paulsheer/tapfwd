
struct randseries;

enum fastsec_result {
    FASTSEC_RESULT_SUCCESS = 0,
    FASTSEC_RESULT_STORAGE_ERROR = 10,
    FASTSEC_RESULT_SOCKET_ERROR = 20,
    FASTSEC_RESULT_SECURITY_ERROR = 30,
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





