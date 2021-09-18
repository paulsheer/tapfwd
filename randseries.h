

struct randseries;

struct randseries *randseries_new (int key_sz);
void randseries_free (struct randseries *s);
void randseries_bytes (struct randseries *s, void *out, int l);
void randseries_next (struct randseries *s, unsigned char *block);


