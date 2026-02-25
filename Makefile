obj-m += kwebdavfs.o

kwebdavfs-objs := main.o super.o inode.o dir.o file.o http.o tls.o

# Kernel build directory — can be overridden by DKMS via dkms.conf MAKE[0]
KVER        ?= $(shell uname -r)
KDIR        ?= /lib/modules/$(KVER)/build
MODULES_DIR ?= /lib/modules/$(KVER)/extra

# CURDIR is set by make itself and survives sudo (unlike PWD)
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

# Build first (as current user), then install with sudo
install: all
	sudo mkdir -p $(MODULES_DIR)
	sudo cp $(CURDIR)/kwebdavfs.ko $(MODULES_DIR)/
	sudo depmod -a $(KVER)
	@echo "Installed to $(MODULES_DIR)/kwebdavfs.ko"
	@echo "Load with: sudo modprobe kwebdavfs"

uninstall:
	sudo rmmod kwebdavfs 2>/dev/null || true
	sudo rm -f $(MODULES_DIR)/kwebdavfs.ko
	sudo depmod -a $(KVER)
	@echo "Module uninstalled"

load:
	sudo modprobe kwebdavfs

unload:
	sudo modprobe -r kwebdavfs

reload: unload load

.PHONY: all clean install uninstall load unload reload