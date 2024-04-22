CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra -lcrypto

.PHONY: all
all: nyufile

nyufile: nyufile.c

.PHONY: clean
clean:
	rm -f *.o nyufile