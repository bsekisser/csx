TARGETS = crt libstd rom

.PHONY: $(TARGETS)

all: rom

clean: $(addsuffix .clean, $(TARGETS))

%.clean:
	$(MAKE) -f makefiles/$*.mk clean

clean-all: $(addsuffix .clean-all, $(TARGETS))

%.clean-all:
	$(MAKE) -f makefiles/$*.mk clean-all

crt:
	$(MAKE) -f makefiles/crt.mk

libstd: crt
	$(MAKE) -f makefiles/libstd.mk

rom: libstd
	$(MAKE) -f makefiles/rom.mk

