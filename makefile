# setup

CFLAGS += -O1
CFLAGS += -march=native
CFLAGS += $(SDL_CFLAGS)
export CFLAGS

#LDLIBS += -L/home/$(USER)/.local/lib
#LDLIBS += -Lgit/libarmvm
	LDLIBS += -larmvm
#LDLIBS += -Lgit/libarm
	LDLIBS += -larm
#LDLIBS += -Lgit/libbse
	LDLIBS += -lbse
LDLIBS += -lcapstone
LDLIBS += $(SDL_LIBS)
export LDLIBS

SDL_CFLAGS := `sdl2-config --cflags`
SDL_LIBS := `sdl2-config --libs`

export SRC_DIR = source

export TARGETs = csx.exe

# build/recipies

include git/makefiles/common.mk


#$(OBJ_TARGET_EXE): git/libarmvm/libarmvm.a

#$(OBJ_TARGET_EXE): git/libarm/libarm.a

#$(OBJ_TARGET_EXE): git/libbse/libbse.a
