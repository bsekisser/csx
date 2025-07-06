# setup

CFLAGS += -O1
CFLAGS += -march=native
CFLAGS += $(SDL_CFLAGS)
export CFLAGS

LDLIBS += -Lgit/libarmvm -larmvm
LDLIBS += -Lgit/libarm -larm
LDLIBS += -Lgit/libbse -lbse
LDLIBS += -lcapstone
LDLIBS += $(SDL_LIBS)
export LDLIBS

SDL_CFLAGS := `sdl2-config --cflags`
SDL_LIBS := `sdl2-config --libs`

export SRC_DIR = source

export TARGET = csx

# build/recipies

include git/libbse/makefiles/common_setup.mk


.PHONY: all
all: $(TARGET_EXE)
#	$(MAKE) -f git/libbse/makefiles/build_exe.mk

$(OBJ_TARGET_EXE): git/libarmvm/libarmvm.a

$(OBJ_TARGET_EXE): git/libarm/libarm.a

$(OBJ_TARGET_EXE): git/libbse/libbse.a


include git/libbse/makefiles/build_exe.mk
include git/libbse/makefiles/common.mk
