KERNELRELEAS	?= $(shell uname -r)
KERNEL_DIR		?= /lib/modules/$(KERNELRELEAS)/build
PWD				:= $(shell pwd)
ccflags-y		+= -I$(src)/include
obj-m			+= xt_RANDMAP.o

MODULE_OPTIONS = 

##########################################
# note on build targets
#
# module-assistant makes some assumptions about targets, namely
#  <modulename>: must be present and build the module <modulename>
#		<modulename>.ko is not enough
# install: must be present (and should only install the module)
#
# we therefore make <modulename> a .PHONY alias to <modulename>.ko
# and remove utils-installation from 'install'
# call 'make install-all' if you want to install everything
##########################################


.PHONY: all clean clean-all install install-all
.PHONY: kmod clean-kmod install-kmod
.PHONY: usrmod clean-usrmod install-usrmod uninstall-usrmod
.PHONY: modprobe xt_RANDMAP

# we don't control the .ko file dependencies, as it is done by kernel
# makefiles. therefore xt_RANDMAP.ko is a phony target actually
.PHONY: xt_RANDMAP.ko

all: kmod usrmod

kmod: xt_RANDMAP.ko
xt_RANDMAP: xt_RANDMAP.ko
xt_RANDMAP.ko: xt_RANDMAP.c nf_nat_proto.inc
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

usrmod:
	$(MAKE) -C $(PWD)/usrmod

clean-all: clean-kmod clean-usrmod

clean: clean-kmod
clean-kmod:
	rm -f *~
	rm -f Module.symvers Module.markers modules.order
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

clean-usrmod:
	$(MAKE) -C $(PWD)/usrmod clean

install-all: install-kmod install-usrmod

install: install-kmod
install-kmod: kmod
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules_install
	depmod -a

install-usrmod:
	$(MAKE) -C $(PWD)/usrmod install

uninstall-usrmod:
	$(MAKE) -C $(PWD)/usrmod uninstall

modprobe: xt_RANDMAP.ko
	chmod a+r xt_RANDMAP.ko
	-rmmod xt_RANDMAP
	insmod ./xt_RANDMAP.ko $(MODULE_OPTIONS)

