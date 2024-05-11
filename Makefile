TOP_DIR = $(PWD)
#TOP_SOURCE = $(TOP_DIR)/source
BUILD_DIR = build-$(shell $(CC) -dumpmachine)
GIT_DIR = $(TOP_DIR)/..

TARGET = csx

#LDLIBS += -lpthread -lm -lSDL2
LDLIBS += -lcapstone
LDLIBS += -L$(GIT_DIR)/libbse -lbse

.PHONY: all

all: $(OBJS) $(TARGET)

clean:
	-rm $(OBJ_DIR)/*.d $(OBJ_DIR)/*.o $(TARGET)

include Makefile.common
