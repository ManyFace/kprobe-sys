#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/uaccess.h>

extern int get_ksyms(void);
extern unsigned long lookup_sym(const char *name);
extern unsigned long lookup_sym_part(const char *name);
extern unsigned long lookup_sym_part_next(const char *name);
unsigned long inst[4];
int inst_num = 0;
mm_segment_t old_fs;

void (*mem_txt_write_spinlock)(unsigned long *flags);
void (*mem_txt_write_spinunlock)(unsigned long *flags);
void (*mem_txt_writeable)(unsigned long addr);
void (*mem_txt_restore)(void);
int mem_text_wp = 0;

static void fake_check_version()
{
        unsigned long start, end;
        unsigned long *p;
        unsigned long flags;

        start = lookup_sym_part("check_version.");
        if (start == 0)
                return;

        printk("check version addr = %p\n", start);
        end = lookup_sym_part_next("check_version.");
        printk("check_version next func addr = %p\n", end);

        mem_txt_write_spinlock = lookup_sym("mem_text_writeable_spinlock");
        if (mem_txt_write_spinlock) {
                mem_txt_write_spinunlock = lookup_sym("mem_text_writeable_spinunlock");
                mem_txt_writeable = lookup_sym("mem_text_address_writeable");
                mem_txt_restore = lookup_sym("mem_text_address_restore");
                mem_text_wp = 1;

        }

        if (mem_text_wp) {

                for (p = end; p > start && inst_num < 4; p--) {
                        if (*p == 0xe3a00000) {
                                mem_txt_write_spinlock(&flags);
                                mem_txt_writeable(p);
                                inst[inst_num++] = p;
                                *p = 0xe3a00001;
                                mem_txt_restore();
                                mem_txt_write_spinunlock(&flags);
                                printk("mem fix %p\n", p);
                        }
                }
        }
        else {
                old_fs = get_fs();
                set_fs(get_ds());
                for (p = end; p > start && inst_num < 4; p--) {
                        if (*p == 0xe3a00000) {
                                inst[inst_num++] = p;
                                *p = 0xe3a00001;
                                printk("fs fix %p\n", p);
                        }
                }
                set_fs(old_fs);
        }
        
}

static void restore_check_version()
{
        unsigned long *p;
        unsigned long cv;
        unsigned long flags;

        cv = lookup_sym_part("check_version.");
        if (cv == 0)
                return;

        if (mem_text_wp) {

                while (inst_num) {
                       p = inst[--inst_num];
                       mem_txt_write_spinlock(&flags);
                       mem_txt_writeable(p);
                       *p = 0xe3a00000;
                       mem_txt_restore();
                       mem_txt_write_spinunlock(&flags);
                       printk("mem restore %p\n", p);
                }
        }
        else {
     
                old_fs = get_fs();
                set_fs(get_ds());
                while (inst_num) {
                        p = inst[--inst_num];
                        *p = 0xe3a00000;
                        printk("fs restore %p\n", p);
                }
                set_fs(old_fs);
        }
}

static int __init h_init(void)
{
        printk("Hello, kernel!\n");

        fake_check_version();
        return 0;
}

static void __exit h_exit(void)
{
        restore_check_version();
        printk("Bye, kernel!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hitmoon <zxq_yx_007@163.com>");

module_init(h_init);
module_exit(h_exit);
