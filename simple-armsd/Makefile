#	$Id: Makefile 20892 2012-01-25 09:27:36Z yamazaki $

CC=gcc
COPTS=-O -Wall -Werror -g
PROG=armsd

CFLAGS+=-I/usr/local/include
LDFLAGS+=-L/usr/local/lib
LIBS=-larms -lssl -lcrypto -lexpat

OBJ =callback.o
OBJ+=main.o

all: $(PROG)

%.o: %.c
	$(CC) $(COPTS) $(CFLAGS) -c -o $@ $<

$(PROG): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

clean:
	rm -f $(PROG) $(OBJ)
