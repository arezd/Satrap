CC=clang
CFLAGS=-g -Wall

.PHONY: clean all

all: simple_request arp_spoof arp_mitm arp_scan

simple_request: simple_request.o arp.o

arp_spoof: arp_spoof.o arp.o

arp_mitm: arp_mitm.o arp.o

arp_scan: arp_scan.o arp.o

%.o: %.c %.h
	$(CC) -c $< $(CFLAGS)

clean:
	rm *.o simple_request arp_spoof arp_mitm arp_scan
