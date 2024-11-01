# Makefile for the Watchpoint Kernel Module

obj-m := watchpoint.o
KDIR := ${KERNEL_SRC}
CFLAGS := ${CFLAGS}
LDFLAGS := ${LDFLAGS}

# Build the kernel module
all:
	make -C $(KDIR) M=$(PWD) modules
	$(MAKE) watchpoint_test  # Compile the test program

# Build the test program
watchpoint_test:
	$(CC) $(CFLAGS) -o watchpoint_test watchpoint_test.c $(LDFLAGS) -lc

# Clean both kernel module and test program artifacts
clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f watchpoint_test