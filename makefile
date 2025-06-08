CFLAGS += -O1 -march=native

LDLIBS += -Lgit/libarmvm -larmvm
LDLIBS += -Lgit/libarm -larm
LDLIBS += -Lgit/libbse -lbse
LDLIBS += -lcapstone
LDLIBS += -lsdl2

SRC_DIR = source
SRCS = $(wildcard $(SRC_DIR)/*.c)

TARGET_EXE = csx

VPATH = source

.PHONY: all
all: $(TARGET_EXE)


include git/libbse/makefile.setup

$(OBJ_TARGET_EXE): git/libarmvm/libarmvm.a

$(OBJ_TARGET_EXE): git/libarm/libarm.a

$(OBJ_TARGET_EXE): git/libbse/libbse.a

include git/libbse/makefile.build
