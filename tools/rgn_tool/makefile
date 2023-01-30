CFLAGS = -Wall -g
CFLAGS += -O2
CFLAGS += -I../fw_info
CFLAGS += -I../../../include

VPATH = ../fw_info

all: rfp

rfp: fwinfo.o garmin_rgn_file_parse.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm rfp *.o
	
