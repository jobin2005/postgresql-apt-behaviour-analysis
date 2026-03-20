#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init start(void)
{
	printk(KERN_ALERT "[JOBIN] Good morning\n");
	return 0;
}

static void __exit end(void)
{
	printk(KERN_ALERT "[JOBIN] Bye\n");
}

module_init(start);
module_exit(end);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jobs");
MODULE_DESCRIPTION("first module");
