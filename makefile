CC = gcc
CFLAGS = -lusb-1.0

all: clean build

clean:
ifneq (,$(wildcard ./ninja))
	rm ninja
endif
build: src/inject.h src/inject.c src/main.c
	$(CC) $(CFLAGS) src/inject.c src/main.c -o ninja
