CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2

all: rootkit.so victim

rootkit.so: src/rootkit.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl

victim: src/victim.c
	$(CC) $(CFLAGS) -o $@ $<

run: all
	LD_PRELOAD=./rootkit.so ./victim

clean:
	rm -f rootkit.so victim

.PHONY: all run clean
