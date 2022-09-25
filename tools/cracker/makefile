CFLAGS = -Wall -g
CFLAGS += -O2
CFLAGS += -I../../../include

OBJS = cracker_main.o
TARGET = cracker

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm $(TARGET) *.o
	
