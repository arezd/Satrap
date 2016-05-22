CC=clang
CFLAGS=-g -Wall

.PHONY: clean all

all: simple_request arp_spoof

simple_request: simple_request.o arp.o

arp_spoof: arp_spoof.o arp.o

%.o: %.c %.h
	$(CC) -c $< $(CFLAGS)

clean:
	rm *.o simple_request arp_spoof
