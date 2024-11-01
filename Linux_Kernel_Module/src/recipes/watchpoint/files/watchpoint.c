#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Serhii Stepanchuk");
MODULE_DESCRIPTION("Kernel Module to Watch Memory Access");
MODULE_VERSION("1.0");

static unsigned int watch_address;
module_param(watch_address, uint, 0000);
MODULE_PARM_DESC(watch_address, "Address to monitor (as an unsigned int)");

static void w_event_handler(struct perf_event *event,
                            struct perf_sample_data *data,
                            struct pt_regs *regs) {
  printk(KERN_INFO "Watchpoint triggered at address 0x%x\n", watch_address);
}

static struct perf_event_attr w_perf_attr = {
    .type = PERF_TYPE_BREAKPOINT,
    .size = sizeof(struct perf_event_attr),
    .config = HW_BREAKPOINT_R |
              HW_BREAKPOINT_W, // Спостерігати за читанням та записом
    .bp_type = HW_BREAKPOINT_X, // Спостерігати за виконанням (необов'язково)
    .bp_len = HW_BREAKPOINT_LEN_1, // Розмір області спостереження (1, 2, 4 або
                                   // 8 байт)
    .sample_period = 1, // Частота збору даних
    .wakeup_events = 1, // Генерувати переривання при кожній події
};

static struct perf_event *w_perf_event;

static int __init watchpoint_init(void) {
  // Створення події perf_event
  w_perf_attr.bp_addr = watch_address; // Встановлення адреси спостереження

  w_perf_event = perf_event_create_kernel_counter(&w_perf_attr, -1, NULL,
                                                  w_event_handler, NULL);
  if (IS_ERR(w_perf_event)) {
    printk(KERN_ERR "perf_event_create_kernel_counter failed\n");
    return PTR_ERR(w_perf_event);
  }

  perf_event_enable(w_perf_event); // Увімкнення події
  printk(KERN_INFO "Watchpoint set at address 0x%x\n", watch_address);
  return 0;
}

static void __exit watchpoint_exit(void) {
  // Вимкнення та звільнення події
  perf_event_disable(w_perf_event);
  perf_event_release_kernel(w_perf_event);
  printk(KERN_INFO "Watchpoint unregistered\n");
}

module_init(watchpoint_init);
module_exit(watchpoint_exit);
