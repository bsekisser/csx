CFLAGS += -ffreestanding
CFLAGS += -march=armv5t
CFLAGS += -mtune=arm926ej-s
#CFLAGS += -mfloat-abi=soft
CFLAGS += -nostdinc
CFLAGS += -nostdlib

CRTI_OBJ = \
	crti.o
CRTBEGIN_OBJ = \
	$(shell $(CC) $(CFLAGS) -print-file-name=crtbegin.o)

CRTEND_OBJ = \
	$(shell $(CC) $(CFLAGS) -print-file-name=crtend.o)
CRTN_OBJ = \
	crtn.o

INCLUDE += -Ilibstd
INCLUDE += -Icrt

LIBS += libstd.a

OBJCOPY_FLAGS += -O binary

SRC_DIR = source



include makefiles/common.mk



all: rom.bin

rom.bin: rom.elf
	$(OBJCOPY) $(OBJCOPY_FLAGS) $< $@

rom.elf: ivt.o $(CRTI_OBJ) $(CRTBEGIN_OBJ) $(OBJS) $(LIBS) $(CRTEND_OBJ) $(CRTN_OBJ)
	$(LD) \
		-Map=$(@).map --cref \
		--print-map-discarded \
		-T linker.ld \
		--start-group $(LIBS) --end-group \
		-o $@ $^

#garmin.a: garmin.a(garmin_rgn_file_parse.o fwinfo.o)
