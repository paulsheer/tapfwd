

CFLAGS = -m64 -maes -Wall -Wextra -O3 -g3
# CFLAGS = -m64 -maes -Wall -Wextra -O0 -g3
# CFLAGS = -m32 -Wall -Wextra -O3 -g3
CC = gcc
SRCS = aes.c curve25519.c curve448.c ipv6scan.c sha256.c tapfwd.c fastsec.c randseries.c symauth.c

tapfwd: $(patsubst %.c,%.o,$(SRCS))
	$(CC) $(CFLAGS) -o tapfwd $(patsubst %.c,%.o,$(SRCS))

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(patsubst %.c,%.o,$(SRCS))
	rm -f tapfwd

