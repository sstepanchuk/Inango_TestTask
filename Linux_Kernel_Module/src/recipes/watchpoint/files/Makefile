# Makefile for the Watchpoint Kernel Module

obj-m := watchpoint.o
KDIR := ${KERNEL_SRC}

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
