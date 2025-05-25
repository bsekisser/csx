INCLUDE += -Ilibstd

SRC_DIR = libstd

include makefiles/common.mk

all: libstd.a

libstd.a: libstd.a($(OBJS))
