CFLAGS = -Wall -g
CFLAGS += -O2
CFLAGS += -I../../../include

all: rfp

rfp: fwinfo.o garmin_rgn_file_parse.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm rfp *.o
	
