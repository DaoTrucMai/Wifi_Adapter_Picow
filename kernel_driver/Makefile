obj-m += pico_usb_wifi.o
pico_usb_wifi-objs := pico_usb_wifi_main.o pico_wifi_cfg80211.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
