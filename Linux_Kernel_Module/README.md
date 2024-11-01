# Kernel Watchpoint

Simple kernel watchpoint with using hardware breakpoints, and sysfs

## Dependencies

* Yocto Project 6.6 (scarthgap)

## Installing

1. Check you have all of the dependencies for Yocto Project
2. Configure and build project
  ```bash
  git submodule update --remote
  source ./poky/oe-init-build-env 
  bitbake core-image-minimal
  ```

## Run

1. Run image (login root)
  ```bash
  runqemu qemux86 nographic slirp 
  ```
2. Second connect by second terminal via ssh
  ```bash
  ssh -p 2222 root@localhost
  ```
3. Run in second terminal this cmd, and copy address from output
  ```bash
  watchpoint_test
  ``` 
4. Run in main terminal kernel module
  ```bash
  insmod /lib/modules/6.6.50-yocto-standard/extra/watchpoint.ko watch_address=<address>
  ```
5. Watchpoint installed on address, you can test it via watchpoint_test (in second termminal, write difrent values)
6. Also you can write and read in sysfs, it's path to sysfs wariable `/sys/kernel/watchpoint/watch_address`

## What I used for testing 

* QEMU x86 emulator 

## Restrictions
  * Can't separate read and write events in hw breakpoint


 




