CC = gcc
CFLAGS = -Wall
TARGETS = opoznienia

all: $(TARGETS)

opoznienia: opoznienia.o err.o parameters.o structs.h measure_delays.o telnet.o server_udp.o
	$(CC) $(CFLAGS) -pthread  $^ -o $@

opoznienia.o: opoznienia.c parameters.c measure_delays.h err.c structs.h telnet.h
	$(CC) $(CFLAGS) -pthread -c $^

telnet.o: err.c structs.h telnet.h telnet.c telnet.h
	$(CC) $(CFLAGS) -pthread -c $^

measure_delays.o: err.c structs.h measure_delays.c measure_delays.h
	$(CC) $(CFLAGS) -pthread -c $^

server_udp.o: err.c structs.h server_udp.c server_udp.h
	$(CC) $(CFLAGS) -pthread -c $^

clean:
	rm -f *.o
