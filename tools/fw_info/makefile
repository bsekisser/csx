CFLAGS = -Wall -g
CFLAGS += -O2
CFLAGS += -I../../../include

TARGET = fwinfo

all: $(TARGET)

$(TARGET): fwinfo.o fwinfo.h main.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm $(TARGET) *.o
	
