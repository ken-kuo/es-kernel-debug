obj-m := es_debug.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
WARN_FLAGS += -Wall

.PHONY: default clean
defualt:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	 rm -rf $(wildcard .*.cmd *.o *.ko *.mod.* .c* .t* Module.symvers *.order *.markers)
