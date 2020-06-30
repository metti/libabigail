obj-m += one_of_each.o

KDIR := /tmp/some/kernel/source/dir

PWD := $(shell pwd)
default:
	make -C $(KDIR) tinyconfig
	pushd $(KDIR); ./scripts/config -e 64BIT -e MODULES -e MODVERSIONS -e CONFIG_DEBUG_INFO; $(MAKE) olddefconfig; popd
	$(MAKE) -C $(KDIR)
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	rm -rf *.mod.c *.o .*.cmd .*.d *.mod modules.order Module.symvers .tmp_versions

clean:
	rm *.ko
