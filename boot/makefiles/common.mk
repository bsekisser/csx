.PRECIOUS: %.o

CC = arm-none-eabi-gcc
LD = arm-none-eabi-ld

CFLAGS += -ffreestanding
#CFLAGS += -mfloat-abi=soft
CFLAGS += -nostdinc
CFLAGS += -nostdlib

CFLAGS += -march=armv5t
CFLAGS += -mtune=arm926ej-s

CFLAGS += -O2

CFLAGS += -MMD -MP
CFLAGS += $(INCLUDE)

INCLUDE += -I$(SRC_DIR)

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, %.o, $(SRCS))

OBJCOPY = objcopy

VPATH += $(SRC_DIR)



all:

clean:
	-rm *.d *.o

clean-all: clean
	-rm *.a *.i *.s *.elf *.bin

-include *.d

