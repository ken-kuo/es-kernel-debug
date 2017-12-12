#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/percpu.h>
#include <linux/sysrq.h>

MODULE_LICENSE("GPL");


static struct dentry *dir = 0;
void test_stack_protector(void);
void test_watchpoint(void);
void test_watchpoint_trigger(void);
void sample_hbp_handler(struct perf_event *bp,
             struct perf_sample_data *data,
             struct pt_regs *regs);
void test_function(int a, int b, int c, int d, int e, int f, int g, int h);
void test_lock(int value);
void test_softlockup(void);
void test_hardlockup(void);
void test_lock_page(void);
void test_wake_unlock_page(void);
void test_find_lock_page(void);
void test_file_dentry(void);
void test_workqueue(void);
void test_task_dump(void);
void test_task_dump_hook(void);

uint32_t test_watch_value = 10;
struct perf_event * __percpu *sample_hbp;
struct perf_event_attr attr;
volatile uint32_t my_lock = 1;
struct work_struct mywork;

static DEFINE_MUTEX(mutex_test_lock);
static DEFINE_SEMAPHORE(sem_test_lock);
static wait_queue_head_t my_wait_queue;
static struct page *test_page;
unsigned char *task_bt_buf;
struct file *es_log_fp;

enum {
	TEST_STACK_PROTECTOR,
	TEST_WATCHPOINT,
	TEST_WATCHPOINT_TRIGGER,
	TEST_FUNCTION,
	TEST_MUTEX_LOCK0,
	TEST_MUTEX_LOCK1 = 5,
	TEST_SEM_LOCK0,
	TEST_SEM_LOCK1,
	TEST_SOFTLOCKUP,
	TEST_HARDLOCKUP,
	TEST_LOCK_PAGE = 10,
	TEST_WAKE_UNLOCK_PAGE,
	TEST_FIND_LOCK_PAGE,
	TEST_FILE_DENTRY,
	TEST_WORKQUEUE,
	TEST_TASK_DUMP = 15,
	TEST_TASK_DUMP_HOOK,
};

static void
work_handler(struct work_struct *work){
	printk("%s\n", __FUNCTION__);
}

#define TASK_BT_BUF_SIZE (8 * 1024)
#define TASK_BT_LOG_FILE "/var/log/es_debug.log"
#define ES_LOG_LINE_MAX 1024
loff_t offset = 0;

struct file *file_open(const char *path, int flags, int rights)
{
	struct file *fp = NULL;
	mm_segment_t oldfs;
	int err = 0;

	offset = 0;
	oldfs = get_fs();
	set_fs(get_ds());
	fp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(fp)) {
		err = PTR_ERR(fp);
		return NULL;
	}
	return fp;
}

void file_close(struct file *fp)
{
	filp_close(fp, NULL);
}

int file_write(struct file *fp, unsigned char *data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret = 0;

	oldfs = get_fs();
	set_fs(get_ds());

	fp->f_op->write(fp, (char *)data, size, &fp->f_pos);
	//offset += vfs_write(fp, data, size, &offset);

	set_fs(oldfs);
	return ret;
}

int es_log_printk(const char *fmt, va_list args)
{
	int r = 0;
	static char textbuf[ES_LOG_LINE_MAX];
	char *text = textbuf;
	size_t text_len = 0;
	unsigned long flags;

	//local_irq_save(flags);
	mutex_lock(&mutex_test_lock);
	text_len = vscnprintf(text, sizeof(textbuf), fmt, args);

	file_write(es_log_fp, text, text_len);

	//local_irq_restore(flags);
	mutex_unlock(&mutex_test_lock);
	return r;
}

void test_task_dump_hook() {
	int cpu;
	printk_func_t *printk_func_p;
	printk_func_t vprintk_func;

	printk_func_p = (printk_func_t *)kallsyms_lookup_name("printk_func");
	for_each_possible_cpu(cpu) {
		vprintk_func = per_cpu(*printk_func_p, cpu);
		printk("cpu %d: printk = %pF\n", cpu, vprintk_func);
	}
}

void test_task_dump() {
	int i;
	printk_func_t *printk_func_p;
	printk_func_t vprintk_func;
	cpumask_t cpus_allowed_ori;

	cpus_allowed_ori = current->cpus_allowed;
	set_cpus_allowed_ptr(current, cpumask_of(smp_processor_id()));

	printk_func_p = (printk_func_t *)kallsyms_lookup_name("printk_func");
 	vprintk_func = this_cpu_read(*printk_func_p);

	task_bt_buf = vmalloc(TASK_BT_BUF_SIZE);

	es_log_fp = file_open(TASK_BT_LOG_FILE, O_RDWR | O_CREAT | O_TRUNC , 0666);
	if (!es_log_fp)
		return;

	this_cpu_write(*printk_func_p, &es_log_printk);

	for (i = 0; i < 200; i++)
		handle_sysrq('t');

	this_cpu_write(*printk_func_p, vprintk_func);

	file_close(es_log_fp);
	vfree(task_bt_buf);

	set_cpus_allowed_ptr(current, &cpus_allowed_ori);
}

void test_workqueue(void) {
	INIT_WORK(&mywork, work_handler);
	schedule_work(&mywork);
}

void recursive_dentry(struct dentry *dentry){
	if (!IS_ROOT(dentry->d_parent))
		recursive_dentry(dentry->d_parent);
	printk(KERN_CONT "/%s", dentry->d_name.name);
}

void find_file(struct inode *inode){
	struct dentry *dentry;
	printk(KERN_INFO
			"current pid = %d "
			"inode i_ino = %lu "
			"i_op = %pF "
			"i_fop = %pF "
			"i_private = 0x%lx, "
			"i_private = %pF "
			"i_count = %d "
			"i_writecount = %d "
			"i_readcount = %d "
			"iminor = %d "
			"imajor = %d "
			/* "i_private(thread pid) = %d " */
			"file = ",
			current->pid,
			inode->i_ino ? inode->i_ino : 0,
			inode->i_op ? inode->i_op : NULL,
			inode->i_fop ? inode->i_fop : NULL,
			inode->i_private ? (unsigned long)inode->i_private : 0x0,
			inode->i_private ? inode->i_private : 0x0,
			atomic_read(&inode->i_count),
			atomic_read(&inode->i_writecount),
			atomic_read(&inode->i_readcount),
			iminor(inode),
			imajor(inode)
			/* inode->i_private ? (*(struct task_struct **)(inode->i_private))->pid : 0x0 */
			);

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		recursive_dentry(dentry);
	}
	spin_unlock(&inode->i_lock);
	printk(KERN_CONT "\n");
}

void find_d_state_on_wq(wait_queue_head_t *wq){
	wait_queue_t *q;
	struct task_struct *p;
	struct wait_bit_queue *bq;
	struct page *page;

	/* check wait entry in wait queue */
	list_for_each_entry(q, &wq->task_list, task_list) {
		p = (struct task_struct *)q->private;
		if (p->state == TASK_UNINTERRUPTIBLE
				&& q->func == wake_bit_function_rh) {
			/* find wait_bit_queue from wait entry */
			bq = container_of(q, struct wait_bit_queue, wait);
			/* find page from wait_bit_queue->key.flags */
			page = container_of(bq->key.flags, struct page, flags);
			printk(KERN_INFO "task = %s(%d) "
					"wait page = 0x%lx "
					"address_space = 0x%lx\n",
					p->comm, p->pid,
					(unsigned long)page,
					(unsigned long)page->mapping
					);
			if (page->mapping && !PageAnon(page)) {
				find_file(page->mapping->host);
			}
		}
	}
}

void test_find_lock_page(void) {
	struct pglist_data **ndp;
	wait_queue_head_t   *wq;

	int zone_idx = 0;
	int wq_idx = 0;
	int wq_num = 0;

	/* per node */
	for (ndp = node_data; *ndp; ndp++){
		/* per zone */
		for (zone_idx = 0; zone_idx < MAX_NR_ZONES; zone_idx++)
		{
			wq = (*ndp)->node_zones[zone_idx].wait_table;
			wq_num =
				(*ndp)->node_zones[zone_idx].wait_table_hash_nr_entries;
			printk(KERN_INFO "wq_num = %d\n", wq_num);
			/* per wait queue */
			for (wq_idx = 0; wq_idx < wq_num; wq_idx++){
				find_d_state_on_wq(&wq[wq_idx]);
			}
		}
	}
}

void test_lock_page(){
	printk(KERN_INFO "lock page 0x%lx ...\n", (unsigned long)test_page);
	lock_page(test_page);
	printk(KERN_INFO "page 0x%lx locked\n", (unsigned long)test_page);

	printk(KERN_INFO "sleep on waitqueue\n");
	sleep_on(&my_wait_queue);
	unlock_page(test_page);
}

void test_file_dentry(void) {
	struct file *fp;
	fp = filp_open("/dev/dm-0", O_RDONLY, 0);
	if (!fp)
		printk(KERN_INFO "file not found\n");
	else
		find_file(fp->f_mapping->host);
	filp_close(fp,NULL);
}

void test_wake_unlock_page(){
	printk(KERN_INFO "wake_up lock process\n");
	wake_up(&my_wait_queue);
}

void test_softlockup(){
	printk(KERN_INFO "%s, processor id = %d\n",
			__FUNCTION__, smp_processor_id());
	while(1);
}

void test_hardlockup(void){
	printk(KERN_INFO "%s, processor id = %d\n",
			__FUNCTION__, smp_processor_id());
	local_irq_disable();
	while(1);
}

void test_lock(int value){
	int lock_time = 0;

	switch (value){
		case TEST_MUTEX_LOCK0:
			lock_time = 10000;
			mutex_lock(&mutex_test_lock);
			printk(KERN_INFO "lock time = %d ms\n", lock_time);
			msleep(lock_time);
			mutex_unlock(&mutex_test_lock);
			break;
		case TEST_MUTEX_LOCK1:
			lock_time = 100;
			mutex_lock(&mutex_test_lock);
			printk(KERN_INFO "lock time = %d ms\n", lock_time);
			msleep(lock_time);
			mutex_unlock(&mutex_test_lock);
			break;
		case TEST_SEM_LOCK0:
			lock_time = 10000;
			down(&sem_test_lock);
			printk(KERN_INFO "lock time = %d ms\n", lock_time);
			msleep(lock_time);
			up(&sem_test_lock);
			break;
		case TEST_SEM_LOCK1:
			lock_time = 100;
			down(&sem_test_lock);
			printk(KERN_INFO "lock time = %d ms\n", lock_time);
			msleep(lock_time);
			up(&sem_test_lock);
			break;
	}
}

void test_function(int a, int b, int c, int d, int e, int f, int g, int h){
	char test_array[30];
	memset(test_array, 22, 30);

	printk(KERN_INFO "%s:%d, tatal = %d\n",
			__FUNCTION__, __LINE__,a + b + c + d + e + f + g + h);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
}

void sample_hbp_handler(struct perf_event *bp,
             struct perf_sample_data *data,
             struct pt_regs *regs)
{
  printk(KERN_INFO "value is changed\n");
  dump_stack();
  printk(KERN_INFO "Dump stack from sample_hbp_handler\n");
  my_lock = 0;
  printk(KERN_INFO  "(%s)current pid = %d, processor id = %d\n",
		  __FUNCTION__, task_pid_nr(current), smp_processor_id());
}

void test_watchpoint_trigger(){
	test_watch_value += 2;
	printk(KERN_INFO  "(%s)current pid = %d, processor id = %d\n",
			__FUNCTION__, task_pid_nr(current), smp_processor_id());
}

void test_watchpoint(){
	hw_breakpoint_init(&attr);
    attr.bp_addr = kallsyms_lookup_name("test_watch_value");

	printk(KERN_INFO  "&test_watch_value = %llx\n",
			(uint64_t)&test_watch_value);
	printk(KERN_INFO  "lookup test_watch_value = %llx\n", attr.bp_addr);

	attr.bp_len = HW_BREAKPOINT_LEN_1;
	attr.bp_type = HW_BREAKPOINT_W ;
	sample_hbp = register_wide_hw_breakpoint(&attr,
			(perf_overflow_handler_t)sample_hbp_handler, NULL);

	printk(KERN_INFO  "(%s)current pid = %d, processor id = %d\n",
			__FUNCTION__, task_pid_nr(current), smp_processor_id());
	while(my_lock);
	unregister_wide_hw_breakpoint(sample_hbp);
}

void test_stack_protector(){
	char buff[64];
	memset(buff, 0x41, 128);
	printk(KERN_INFO "%s:%d\n", __FUNCTION__, __LINE__);
}

static int write_op(void *data, u64 value)
{
	printk(KERN_INFO  "write value: %llu\n", value);

	switch (value){
		case TEST_STACK_PROTECTOR:
			test_stack_protector();
			break;
		case TEST_WATCHPOINT:
			test_watchpoint();
			break;
		case TEST_WATCHPOINT_TRIGGER:
			test_watchpoint_trigger();
			break;
		case TEST_FUNCTION:
			test_function(value + 1, value + 2, value + 3, value + 4,
					value + 5, value + 6, value + 7,value +9);
			break;
		case TEST_MUTEX_LOCK0:
		case TEST_MUTEX_LOCK1:
		case TEST_SEM_LOCK0:
		case TEST_SEM_LOCK1:
			test_lock(value);
			break;
		case TEST_SOFTLOCKUP:
			test_softlockup();
			break;
		case TEST_HARDLOCKUP:
			test_hardlockup();
			break;
		case TEST_LOCK_PAGE:
			test_lock_page();
			break;
		case TEST_WAKE_UNLOCK_PAGE:
			test_wake_unlock_page();
			break;
		case TEST_FIND_LOCK_PAGE:
			test_find_lock_page();
			break;
		case TEST_FILE_DENTRY:
			test_file_dentry();
			break;
		case TEST_WORKQUEUE:
			test_workqueue();
			break;
		case TEST_TASK_DUMP:
			test_task_dump();
			break;
		case TEST_TASK_DUMP_HOOK:
			test_task_dump_hook();
			break;
		default:
			break;
	}


	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_fops, NULL, write_op, "%llu\n");

int init_module(void)
{
    struct dentry *junk;

	printk(KERN_INFO "=== escore debug start ===\n");

    dir = debugfs_create_dir("es_debug", 0);
    if (!dir) {
        printk(KERN_ALERT "failed to create /sys/kernel/debug/es_debug\n");
        return -1;
    }

    junk = debugfs_create_file(
            "test",
            0222,
            dir,
            NULL,
            &debug_fops);
    if (!junk) {
        printk(KERN_ALERT "failed to create es_debug\n");
        return -1;
    }

	init_waitqueue_head(&my_wait_queue);
	test_page = alloc_page(GFP_KERNEL);

    return 0;
}

void cleanup_module(void)
{
    debugfs_remove_recursive(dir);

	__free_page(test_page);

	printk(KERN_INFO "=== escore debug end ===\n");
}
