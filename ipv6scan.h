

struct iprange_list;
struct iprange_list *iprange_parse (const char *text, int *consumed__);
void iprange_to_text (struct iprange_list *l, char *out, int outlen);
int iprange_match (struct iprange_list *l, const void *a, int addrlen);
void iprange_free (struct iprange_list *l);
int text_to_ip (const char *s, int *consumed_, void *out, int *addr_len);
void ip_to_text (const void *ip, int addrlen, char *out);






