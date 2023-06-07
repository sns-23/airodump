CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -lpcap -lpthread
OBJS = main.o list.o util.o

airodump: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f airodump *.o

.PHONY:
	airodump clean