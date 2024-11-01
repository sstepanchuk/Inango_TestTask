#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Serhii Stepanchuk");
MODULE_DESCRIPTION("Kernel Module to Watch Memory Access");
MODULE_VERSION("1.0");

static unsigned int watch_address; // Always 32-bit for x32 systems
// hw_breakpoint
// static struct perf_event *__percpu *w_perf_event = NULL;
// static struct perf_event *__percpu *r_perf_event = NULL;

static struct perf_event *__percpu *rw_perf_event = NULL;

module_param(watch_address, uint, 0000);
MODULE_PARM_DESC(watch_address, "Address to monitor (as an unsigned int)");

// FUNC Defs
static void disable_watchpoint(struct perf_event *__percpu **pevent,
                               const char *tag);
static int set_watchpoint(unsigned int address,
                          struct perf_event *__percpu **pevent,
                          uint32_t bp_type, perf_overflow_handler_t triggered,
                          const char *tag);
/*static void read_event_handler(struct perf_event *event,
                               struct perf_sample_data *data,
                               struct pt_regs *regs);
static void write_event_handler(struct perf_event *event,
                                struct perf_sample_data *data,
                                struct pt_regs *regs);*/

static void read_write_event_handler(struct perf_event *event,
                                     struct perf_sample_data *data,
                                     struct pt_regs *regs);

// Sysfs attribute functions
static ssize_t watch_address_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf) {
  return snprintf(buf, PAGE_SIZE, "0x%x\n", watch_address);
}

static ssize_t watch_address_store(struct kobject *kobj,
                                   struct kobj_attribute *attr, const char *buf,
                                   size_t count) {
  int ret;
  if (kstrtouint(buf, 16, &watch_address) == 0) {
    printk(KERN_INFO "Updating watch address to 0x%x from sysfs\n",
           watch_address);

    if ((ret = set_watchpoint(watch_address, &rw_perf_event, HW_BREAKPOINT_RW,
                              read_write_event_handler, "read/write")) < 0)
      return ret;

    /*if ((ret = set_watchpoint(watch_address, &r_perf_event, HW_BREAKPOINT_R,
                              read_event_handler, "read")) < 0)
      return ret;

    if ((ret = set_watchpoint(watch_address, &w_perf_event, HW_BREAKPOINT_W,
                              write_event_handler, "write")) < 0) {
      disable_watchpoint(&r_perf_event, "read");
      return ret;
    }*/

    printk(KERN_INFO "Watch address updated to 0x%x from sysfs\n",
           watch_address);
  }
  return count;
}

// Sysfs
static struct kobject *watchpoint_kobj;
static struct kobj_attribute watch_address_attribute =
    __ATTR(watch_address, 0664, watch_address_show, watch_address_store);

/*static void read_event_handler(struct perf_event *event,
                               struct perf_sample_data *data,
                               struct pt_regs *regs) {
  printk(KERN_INFO "Read watchpoint triggered at address 0x%x\n",
         watch_address);
  dump_stack();
}

static void write_event_handler(struct perf_event *event,
                                struct perf_sample_data *data,
                                struct pt_regs *regs) {
  printk(KERN_INFO "Write watchpoint triggered at address 0x%x\n",
         watch_address);
  dump_stack();
}*/

static void read_write_event_handler(struct perf_event *event,
                                     struct perf_sample_data *data,
                                     struct pt_regs *regs) {
  printk(KERN_INFO "Read/Write watchpoint triggered at address 0x%x\n",
         watch_address);
  dump_stack();
}

static int set_watchpoint(unsigned int address,
                          struct perf_event *__percpu **pevent,
                          uint32_t bp_type, perf_overflow_handler_t triggered,
                          const char *tag) {
  printk(KERN_INFO "%s watchpoint initializing on 0x%x\n", tag, address);

  if (*pevent)
    disable_watchpoint(pevent, tag);

  struct perf_event_attr attr;
  hw_breakpoint_init(&attr);
  attr.bp_addr = (unsigned long)address;
  attr.bp_len = sizeof(address);
  attr.bp_type = bp_type;

  *pevent = register_wide_hw_breakpoint(&attr, triggered, NULL);
  if (IS_ERR((void __force *)*pevent)) {
    int ret = PTR_ERR((void __force *)*pevent);
    printk(KERN_ERR
           "[%s] register_wide_hw_breakpoint failed on address 0x%x: %d\n",
           tag, address, ret);
    *pevent = NULL;
    return ret;
  }
  printk(KERN_INFO "%s watchpoint initialized on 0x%x\n", tag, address);

  return 0;
}

static void disable_watchpoint(struct perf_event *__percpu **pevent,
                               const char *tag) {
  unregister_wide_hw_breakpoint(*pevent);
  printk(KERN_INFO "%s watchpoint removed from address 0x%x\n", tag,
         (unsigned int)hw_breakpoint_addr(*this_cpu_ptr(*pevent)));
  *pevent = NULL;
}

static int __init watchpoint_init(void) {
  int ret;
  // enable watchpoint
  if ((ret = set_watchpoint(watch_address, &rw_perf_event, HW_BREAKPOINT_RW,
                            read_write_event_handler, "read")) < 0)
    return ret;

  /*if ((ret = set_watchpoint(watch_address, &r_perf_event, HW_BREAKPOINT_R,
                            read_event_handler, "read")) < 0)
    return ret;

  if ((ret = set_watchpoint(watch_address, &w_perf_event, HW_BREAKPOINT_W,
                            write_event_handler, "write")) < 0) {
    disable_watchpoint(&r_perf_event, "read");
    return ret;
  }*/

  // enable sysfs
  watchpoint_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
  if (!watchpoint_kobj) {
    // disable_watchpoint(&r_perf_event, "read");
    // disable_watchpoint(&w_perf_event, "write");
    disable_watchpoint(&rw_perf_event, "read/write");
    printk(KERN_ERR "kobject_create_and_add failed\n");
    return -ENOMEM;
  }

  if ((ret = sysfs_create_file(watchpoint_kobj,
                               &watch_address_attribute.attr)) < 0) {
    kobject_put(watchpoint_kobj);
    // disable_watchpoint(&r_perf_event, "read");
    // disable_watchpoint(&w_perf_event, "write");
    disable_watchpoint(&rw_perf_event, "read/write");
    printk(KERN_ERR "sysfs_create_file failed\n");
    return ret;
  }

  return 0;
}

static void __exit watchpoint_exit(void) {
  // disable sysfs
  sysfs_remove_file(watchpoint_kobj, &watch_address_attribute.attr);
  kobject_put(watchpoint_kobj);

  // disbale watchpoints
  /*if (r_perf_event)
    disable_watchpoint(&r_perf_event, "read");
  if (w_perf_event)
    disable_watchpoint(&w_perf_event, "write");*/

  if (rw_perf_event)
    disable_watchpoint(&rw_perf_event, "read/write");
}

module_init(watchpoint_init);
module_exit(watchpoint_exit);
