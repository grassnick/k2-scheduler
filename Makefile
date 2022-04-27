PWD	:= $(shell pwd)
KDIR	?= /lib/modules/$(shell uname -r)/build

k2_legacy-y := k2.o
obj-m += k2_legacy.o

all: default

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
