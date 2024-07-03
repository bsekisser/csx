CFLAGS += -O1 -march=native

LDLIBS += -Lgit/libarmvm -larmvm
LDLIBS += -Lgit/libarm -larm
LDLIBS += -Lgit/libbse -lbse
LDLIBS += -lcapstone

SRC_DIR = source
SRCS = $(wildcard $(SRC_DIR)/*.c)

TARGET_EXE = csx

VPATH = source

.PHONY: all
all: $(TARGET_EXE)


include git/libbse/makefile.setup
include git/libbse/makefile.build
