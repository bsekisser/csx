TOP_DIR = $(PWD)
#TOP_SOURCE = $(TOP_DIR)/source
BUILD_DIR = build-$(shell $(CC) -dumpmachine)

TARGET = csx

#LDFLAGS += -lpthread -lm -lSDL2
LDFLAGS += -lcapstone

.PHONY: all

all: $(OBJS) $(TARGET)

clean:
	-rm $(OBJ_DIR)/*.d $(OBJ_DIR)/*.o $(TARGET)

include Makefile.common
