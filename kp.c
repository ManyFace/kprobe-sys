#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/pagemap.h>
#include <asm/cacheflush.h>
#include <linux/fdtable.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/workqueue.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>

#define MODULE_NAME "kp"
#define MAX_CONF 4096
#define MAX_LOG  4096
#define MAX_ENTRY 256
#define MAX_COMM  256
#define MAX_BUF  1024 * 1024

#ifdef DEBUG
#define dprint(fmt, args...) printk(fmt, ##args)
#else
#define dprint(fmt, args...) do {} while (0)
#endif


static struct my_data {
        char *conf;
        char *log;
        unsigned long log_index;
        unsigned long log_len;
        spinlock_t lock;
} hook_data;

typedef struct {
        struct work_struct work;
        char *filename;
}my_work_t;

static struct workqueue_struct *my_wq;
my_work_t *work;

/* pattern string */
static char *pat = ".so";

module_param(pat, charp, 0000);
MODULE_PARM_DESC(pat, "pattern string passed to hook");
        
char comm[MAX_COMM] = {0};
char tmp[MAX_ENTRY] = {0};

static struct proc_dir_entry *hook_dir, *hook_conf, *hook_log;

static struct file *kopen_file(const char *path, int flags, umode_t mode)
{
        struct file *file = NULL;
        mm_segment_t old_fs = get_fs();
        set_fs(KERNEL_DS);

        file = filp_open(path, flags, mode);
        set_fs(old_fs);

        if (IS_ERR(file)) {
                return NULL;
        }
        return file;
}

static void kclose_file(struct file *file)
{
        filp_close(file, NULL);
}

static ssize_t kread_file(struct file *file, char *buf, size_t size)
{
        ssize_t ret = -1;
        loff_t pos = 0;

        mm_segment_t old_fs = get_fs();
        set_fs(KERNEL_DS);
        if (file) {
                ret = vfs_read(file, buf, size, &pos);

        }
        set_fs(old_fs);
        
        return ret;
}
        

static ssize_t kwrite_file(struct file *file, char *data, size_t size)
{
        ssize_t ret = -1;
        loff_t pos = 0;
        mm_segment_t old_fs = get_fs();
        set_fs(KERNEL_DS);
        
        if (file) {
                ret = vfs_write(file, data, size, &pos);
        }
        set_fs(old_fs);

        return ret;
}
                       
/*
static void log_to_user(const char *call, const char *comm, const char *filename)
{
        int ret;
        char pid[16];
        char uid[16];
        char euid[16];


        char path[] = "/data/logger";
        char *argv[] = {path,
                        call,
                        filename,
                        pid,
                        uid,
                        euid,
                        comm,
                        NULL};
        char *envp[] = {"HOME=/",
                        "PATH=/system/sbin:/system/bin:/system/xbin",
                        NULL};

        sprintf(pid, "%d", current->pid);
        sprintf(uid, "%d", current->cred->uid);
        sprintf(euid, "%d", current->cred->euid);
        
        ret = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
        if (ret != 0)
                printk(KERN_INFO "Write log error!\n");
        
}
*/

static int do_log(const char *fmt, ...)
{
        int tlen, len;
        char *p = NULL;
        char *tmp = NULL;
        va_list args;

        tmp = kmalloc(512, GFP_ATOMIC);
        if (tmp == NULL) {
                printk("can not get memory for pre log, skip write!\n");
                return -1;
        }

        va_start(args, fmt);
        vsnprintf(tmp, INT_MAX, fmt, args);
        va_end(args);

        len = strlen(tmp);
        tlen = hook_data.log_index + len;
        spin_lock(&hook_data.lock);
        if (tlen > hook_data.log_len) {
                tlen = (tlen / MAX_LOG + 1) * MAX_LOG;
                p = kmalloc(tlen, GFP_ATOMIC);
                if (p == NULL) {
                        printk("log to /proc/%s/log failed!\n", MODULE_NAME);
                        len = -1;
                        goto out;
                }
                // copy old log
                hook_data.log_len = tlen;
                strncpy(p, hook_data.log, hook_data.log_index);
                kfree(hook_data.log);
                hook_data.log = p;
        }

        strcat(hook_data.log + hook_data.log_index, tmp);
        hook_data.log_index += len;

out:
        spin_unlock(&hook_data.lock);
        kfree(tmp);
        return len;
}

static void write_log(const char *call, const char *filename,
                      pid_t pid, uid_t uid, uid_t euid,
                      const char *comm) {
        char timev[64];
        struct timeval time;
        unsigned long local_time;
        struct rtc_time tm;

        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &tm);

        sprintf(timev, "%04d-%02d-%02d %02d:%02d:%02d",
                tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        do_log("%s\t%s\t%s\t%d\t%d\t%d\t%s\n",
                call, timev, comm, uid, euid, pid, filename);
}

/* return 1 to pass filter */
static int hook_filter(const char *comm)
{
        char entry[MAX_ENTRY];
        char *h, *t;
        int len = strlen(hook_data.conf);
        int find = 0;


        if (!strcmp(comm, ""))
                return 0;
        
        if (!strcmp(hook_data.conf, ""))
                return 0;

        h = hook_data.conf;
        while(h - hook_data.conf <= len) {
                t = strstr(h, "\n");
                if (t == NULL)
                        return 0;
                strncpy(entry, h, t - h);
                entry[t - h] = '\0';
                 h = t + 1;

                if (strstr(comm, entry)) {
                        find = 1;
                        break;
                }
        }

        if (find)
                return 1;
        return 0;
        
}

static int __read_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
                              unsigned long addr, void *buf, int len)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages(tsk, mm, addr, 1,
				0, 1, &page, &vma);
		if (ret <= 0) {
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
#ifdef CONFIG_HAVE_IOREMAP_PROT
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, 0);
			if (ret <= 0)
#endif
				break;
			bytes = ret;
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);

                        copy_from_user_page(vma, page, addr,
                                            buf, maddr + offset, bytes);
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}


int read_process_vm(struct task_struct *tsk, unsigned long addr,
                      void *buf, int len)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = __read_remote_vm(tsk, mm, addr, buf, len);
	mmput(mm);

	return ret;
}

/* get executable command from task_struct */
static int get_command(struct task_struct *task, char * buffer)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);
	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;	/* Shh! No looking before we're done */

 	len = mm->arg_end - mm->arg_start;
 
	if (len > PAGE_SIZE)
		len = PAGE_SIZE;
 
	res = read_process_vm(task, mm->arg_start, buffer, len);

	// If the nul at the end of args has been overwritten, then
	// assume application is using setproctitle(3).
	if (res > 0 && buffer[res-1] != '\0' && len < PAGE_SIZE) {
		len = strnlen(buffer, res);
		if (len < res) {
		    res = len;
		} else {
			len = mm->env_end - mm->env_start;
			if (len > PAGE_SIZE - res)
				len = PAGE_SIZE - res;
			res += read_process_vm(task, mm->env_start, buffer+res, len);
			res = strnlen(buffer, res);
		}
	}
out_mm:
	mmput(mm);
out:
	return res;
}

static int  proc_read_conf(char *page, char **start, off_t off, int count,
                      int *eof, void *data)
{
        int len;

        len = sprintf(page, "%s", hook_data.conf);
        return len;
}

static int proc_write_conf(struct file *file, const char *buffer, unsigned long count, void *data)
{
        int len;

        if (count > MAX_CONF)
                len = MAX_CONF;
        else
                len = count;
        if (copy_from_user(hook_data.conf, buffer, len))
                return -EFAULT;
        hook_data.conf[len] = '\0';

        return len;
}

static asmlinkage long jp_sys_open(const char __user *filename, int flags, umode_t mode)
{
        if (!((flags & O_WRONLY) || (flags & O_RDWR)
              || (flags & O_APPEND) || (flags & O_CREAT)))
                goto out;

        get_command(current, comm);
        if (hook_filter(comm)) {
                dprint("sys_open probed, comm = %s\n", comm);
                write_log("open", filename, current->pid, current->cred->uid,
                          current->cred->euid, comm);
        }
out:
        jprobe_return();
        return 0;
}

static void copy_file(const char *filename)
{
        char cf[MAX_ENTRY];
        struct file *cfp = NULL;
        struct file *file = NULL;
        char *ch;
        char *buf;
        ssize_t ret;

        file = kopen_file(filename, O_RDONLY, 0);
        if (file == NULL) {
                printk("can not open file %s\n", filename);
                return;
        }
        
        /* get buf to write so */
        buf = kmalloc(MAX_BUF, GFP_KERNEL);
        if (buf == NULL) {
                printk("not enough memory to write so file\n");
                goto out;
        }

        /* read file into buf */
        ret = kread_file(file, buf, MAX_BUF);
        if (ret < 0) {
                printk("read file %s error!\n", filename);
                goto out1;
        }

        /* make a copy */
        ch = strrchr(filename, '/');
        sprintf(cf, "/sdcard/%s-clone",
                ch ? ch + 1 : filename);
        cfp = kopen_file(cf, O_WRONLY | O_CREAT, 0644);
        if (cfp == NULL) {
                printk("can not create file %s!\n", cf);
                goto out1;
        }

        kwrite_file(cfp, buf, ret);
        kclose_file(cfp);
        do_log("## Write a copy of file %s to %s\n", filename, cf);
out1:
        kfree(buf);
out:
        kclose_file(file);
}

static void wq_function(struct work_struct *work)
{
        my_work_t *my_work = (my_work_t *)work;

        copy_file(my_work->filename);
        kfree(my_work->filename);
        kfree(work);
}

static asmlinkage long jp_sys_close(unsigned int fd)
{
        int flags;
        struct file *file = NULL;
        char *filename;

        file = fget(fd);

        if (file) {
                flags = file->f_flags;
                if (!((flags & O_WRONLY) || (flags & O_RDWR)
                      || (flags & O_APPEND) || (flags & O_CREAT))) {
                        goto out;
                }
                /* get file's name been closed */
                filename = d_path(&file->f_path, tmp, MAX_ENTRY);

        }

        get_command(current, comm);
        if (hook_filter(comm)) {
                dprint("sys_close probed, comm = %s\n", comm);
                //log_to_user("close", comm, filename);
                write_log("close", filename, current->pid,
                          current->cred->uid,
                          current->cred->euid, comm);
                if (strstr(filename, pat)) {
                        // init a work to perform the copy 
                        work = (my_work_t*)kmalloc(sizeof(my_work_t), GFP_ATOMIC);
                        if (work == NULL) {
                                printk(KERN_INFO "can not alloc my_work_t!\n");
                                goto out;
                        }
                        work->filename = kmalloc((strlen(filename) + 1), GFP_ATOMIC);
                        if (work->filename == NULL) {
                                printk(KERN_INFO "can not get memory"
                                       " for my_work->filename\n");
                                goto out;
                        }
                        strcpy(work->filename, filename);
                        INIT_WORK((struct work_struct *)work, wq_function);
                        queue_work(my_wq, (struct work_struct *)work);
                }
        }

        
out:
        if (file)
                fput(file);
        jprobe_return();
        return 0;
}

static asmlinkage int jp_sys_execve(const char __user *filenamei,
                                    const char __user *const __user *argv,
                                    const char __user *const __user *envp,
                                    struct pt_regs *regs)
{
        get_command(current, comm);
        if (hook_filter(filenamei)) {
                dprint("sys_execve probed, comm = %s\n", filenamei);
                //log_to_user("execve", comm, filenamei);
                write_log("execve", filenamei, current->pid,
                          current->cred->uid,
                          current->cred->euid, comm);
        }

        jprobe_return();
        return 0;
}

static asmlinkage long jp_sys_creat(const char __user *pathname, umode_t mode)
{
        get_command(current, comm);
        if (hook_filter(comm)) {
                dprint("sys_creat probed, comm = %s\n", comm);
                write_log("creat", pathname, current->pid, current->cred->uid,
                          current->cred->euid, comm);
        }

        jprobe_return();
        return 0;
        
}

static struct jprobe sys_jprobe_open = {
        .entry = jp_sys_open,
        .kp = {
                .symbol_name = "sys_open",
        },
};

static struct jprobe sys_jprobe_close = {
        .entry = jp_sys_close,
        .kp = {
                .symbol_name = "sys_close",
        },
};

static struct jprobe sys_jprobe_execve = {
        .entry = jp_sys_execve,
        .kp = {
                .symbol_name = "sys_execve",
        },
};

static struct jprobe sys_jprobe_creat = {
        .entry = jp_sys_creat,
        .kp = {
                .symbol_name = "sys_creat",
        },
};

static int log_show(struct seq_file *m, void *v)
{
        seq_printf(m, "%s", hook_data.log);
        return 0;
}

static int log_open(struct inode *inode, struct file *file)
{
        return single_open(file, log_show, NULL);
}

static const struct file_operations log_fops = {
        .owner = THIS_MODULE,
        .open = log_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};


static int __init kp_init(void)
{
        int ret = -ENOMEM;

        hook_dir = proc_mkdir(MODULE_NAME, NULL);
        if (hook_dir == NULL) {
                printk("can not create /proc/%s dir!\n", MODULE_NAME);
                goto out;
        }

        hook_conf = create_proc_entry("conf", 0644, hook_dir);
        if (hook_conf == NULL) {
                printk("can not create /proc/%s/conf file!\n", MODULE_NAME);
                goto no_conf_file;
        }
        hook_data.conf = kmalloc(MAX_CONF, GFP_KERNEL);
        if (hook_data.conf == NULL) {
                printk("no memory for hook_data.conf!\n");
                goto no_conf;
        }

        hook_conf->data = hook_data.conf;
        hook_conf->read_proc = proc_read_conf;
        hook_conf->write_proc = proc_write_conf;

        // hook log
        hook_data.log = kmalloc(MAX_LOG, GFP_KERNEL);
        if (hook_data.log == NULL) {
                printk("no momery for hook_data.log!\n");
                goto no_log;
        }

        hook_data.log_len = MAX_LOG;
        hook_data.log_index = 0;
        spin_lock_init(&hook_data.lock);
        do_log("call\ttime\t\t\tcommand\t\tuid\teuid\tpid\tfile\n");
        
        hook_log = proc_create("log", 0, hook_dir, &log_fops);
        //hook_log = create_proc_entry("log", 0444, hook_dir);
        if (hook_log == NULL) {
                printk("can not create /proc/%s/log file!\n", MODULE_NAME);
                goto no_log_file;
        }

        printk(KERN_INFO "proc file setup success!\n");

        // create workqueue
        my_wq = create_workqueue("my_queue");
        if (my_wq == NULL) {
                printk(KERN_INFO "can not create workqueue!\n");
                goto no_wq;
        }
        printk(KERN_INFO "workqueue create success!\n");
        
        ret = register_jprobe(&sys_jprobe_open);

        if (ret < 0) {
                printk(KERN_INFO "register jprobe failed, return %d", ret);
                goto out1;
        }
        printk(KERN_INFO "Probe for sys_open at %p, handler addr %p\n", sys_jprobe_open.kp.addr, sys_jprobe_open.entry);

        ret = register_jprobe(&sys_jprobe_close);

        if (ret < 0) {
                printk(KERN_INFO "register jprobe failed, return %d", ret);
                goto out2;
        }
        printk(KERN_INFO "Probe for sys_close at %p, handler addr %p\n", sys_jprobe_close.kp.addr, sys_jprobe_close.entry);


        ret = register_jprobe(&sys_jprobe_execve);

        if (ret < 0) {
                printk(KERN_INFO "register jprobe failed, return %d", ret);
                goto out3;
        }
        printk(KERN_INFO "Probe for sys_execve at %p, handler addr %p\n", sys_jprobe_execve.kp.addr, sys_jprobe_execve.entry);

        ret = register_jprobe(&sys_jprobe_creat);

        if (ret < 0) {
                printk(KERN_INFO "register jprobe failed, return %d", ret);
                goto out4;
        }
        printk(KERN_INFO "Probe for sys_creat at %p, handler addr %p\n", sys_jprobe_creat.kp.addr, sys_jprobe_creat.entry);

        printk("hook so file name pat = \"%s\"\n", pat);
        printk("module %s initialized success!\n", MODULE_NAME);
        
        return 0;

out4:
        unregister_jprobe(&sys_jprobe_execve);
out3:
        unregister_jprobe(&sys_jprobe_close);
out2:
        unregister_jprobe(&sys_jprobe_open);
out1:
        destroy_workqueue(my_wq);

no_wq:
        remove_proc_entry("log", hook_dir);
        
no_log_file:
        kfree(hook_data.log);

no_log:
        kfree(hook_data.conf);

no_conf:
        remove_proc_entry("conf", hook_dir);
        
no_conf_file:
        remove_proc_entry(MODULE_NAME, NULL);
out:
        return ret;
}


static void __exit kp_exit(void)
{

        /* remove probes */
        unregister_jprobe(&sys_jprobe_open);
        printk("Probe for sys_open at %p unregistered!\n", sys_jprobe_open.kp.addr);
        unregister_jprobe(&sys_jprobe_close);
        printk("Probe for sys_close at %p unregistered!\n", sys_jprobe_close.kp.addr);
        unregister_jprobe(&sys_jprobe_execve);
        printk("Probe for sys_execve at %p unregistered!\n", sys_jprobe_execve.kp.addr);
        unregister_jprobe(&sys_jprobe_creat);
        printk("Probe for sys_creat at %p unregistered!\n", sys_jprobe_creat.kp.addr);


        /* destroy workqueue */
        flush_workqueue(my_wq);
        destroy_workqueue(my_wq);

        printk(KERN_INFO "workqueue destroyed!\n");

        /* remove proc entries */
        remove_proc_entry("conf", hook_dir);
        kfree(hook_data.conf);
        remove_proc_entry("log", hook_dir);
        kfree(hook_data.log);
        remove_proc_entry(MODULE_NAME, NULL);

        printk(KERN_INFO "proc file destroyed!\n");
        printk(KERN_INFO "module %s removed!\n", MODULE_NAME);
}


module_init(kp_init);
module_exit(kp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hitmoon <zxq_yx_007@163.com>");
