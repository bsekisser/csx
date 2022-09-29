TOP_DIR = $(PWD)
#BUILD_DIR = ../../build-$(shell $(CC) -dumpmachine)
BUILD_DIR = build-$(shell $(CC) -dumpmachine)
#CFLAGS = -Wall -g
#CFLAGS += -O2

INCLUDE += -I../../../include

#OBJS = cracker_arm.o \
#	cracker_main.o \
#	cracker_strings.o

TARGET = cracker

all: $(OBJS) $(TARGET)

#$(TARGET): $(OBJS)
#	$(CC) $(CFLAGS) $^ -o $@

#clean:
#	-rm $(TARGET) *.o

clean:
	-rm $(OBJ_DIR)/*.o $(TARGET)
	
include ../../Makefile.common
