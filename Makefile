CC = gcc
CFLAGS = -Wall -Wextra -g

all: dns

dns: dns.c
	$(CC) $(CFLAGS) dns.c -o dns

clean:
	rm -f dns