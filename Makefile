TOP_DIR = $(PWD)
#TOP_SOURCE = $(TOP_DIR)/source
BUILD_DIR = build-$(shell $(CC) -dumpmachine)

TARGET = csx

#LDLIBS += -lpthread -lm -lSDL2
LDLIBS += -lcapstone
LDLIBS += -L$(TOP_DIR)/../libbse -lbse

.PHONY: all

all: $(OBJS) $(TARGET)

$(TARGET): $(TOP_DIR)/../libbse/libbse.a

clean:
	-rm $(OBJ_DIR)/*.d $(OBJ_DIR)/*.o $(TARGET)

include Makefile.common
