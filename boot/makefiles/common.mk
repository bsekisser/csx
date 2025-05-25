.PRECIOUS: *.o

CC = arm-none-eabi-gcc
LD = arm-none-eabi-ld

CFLAGS += -MMD -MP
CFLAGS += -O2
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

