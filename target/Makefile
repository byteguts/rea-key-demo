CC ?= gcc
CFLAGS ?= -O2 -Wall

syncd: syncd.c
	$(CC) $(CFLAGS) -o syncd syncd.c
	strip syncd

clean:
	rm -f syncd

.PHONY: clean
