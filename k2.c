// SPDX-License-Identifier: GPL-2.0
/*
 * K2 - A prototype of a work-constraining I/O scheduler
 *
 * Copyright (c) 2019, Till Miemietz, 2021-2022 Georg Graßnick
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <trace/events/block.h>

#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/elevator.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

// Tracing related
#define CREATE_TRACE_POINTS

#include "k2_trace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(k2_completed_request);

// Device and ioctl related
#include "k2.h"

// Ringbuffer implementation
#include "ringbuf.h"

/** Macro to disable Kernel massages meant for debugging */
#define K2_LOG(log)

/**
 * @brief Reserve certain percentage for synchronous requests.
 * @details To avoid starvation for synchronous requests, that are restricted from entering the software queues by the high pressure of incoming asynchronous requests,
 * we limit the amount of async requests in the software queues. This value is chooses by hand via quick minimal benchmarks and subject for future optimizations.
 */
#define K2_ASYNC_PERCENTAGE 30

/** A type that represents the latency of a request */
typedef ktime_t latency_ns_t;
#define LATENCY_NS_T_MAX KTIME_MAX

/** A type that represents a point in time */
typedef ktime_t timepoint_ns_t;
#define TIMEPOINT_NS_T_MAX KTIME_MAX

/** The number of requests that can always be in flight, needs to be > 0, else scheduler might stall */
#define K2_MINIMUM_COHERENT_REQUEST_COUNT 2U
static_assert(K2_MINIMUM_COHERENT_REQUEST_COUNT > 0);
static_assert(K2_MINIMUM_COHERENT_REQUEST_COUNT < U64_MAX);

#define K2_REQUEST_RETRY_COUNT_RT_CONSTRAINT 64U
static_assert(K2_REQUEST_RETRY_COUNT_RT_CONSTRAINT > 0);
static_assert(K2_REQUEST_RETRY_COUNT_RT_CONSTRAINT < U16_MAX);

// The assumptions made, to store request data in the elv pointer fields in the request
// assumes, pointer with is 64bit
static_assert(sizeof(void *) == sizeof(u64),
	      "Pointers are required to be 64 bit wide");

#define K2_INTERPOLATION_VAL_COUNT 4U

#define K2_RR_512_LAT 70000
#define K2_RR_4096_LAT 72000
#define K2_RR_508K_LAT 546000
#define K2_RR_2M_LAT 1892000

#define K2_SR_512_LAT 14000
#define K2_SR_4096_LAT 15000
#define K2_SR_508K_LAT 158000
#define K2_SR_2M_LAT 599000

#define K2_RW_512_LAT 15000
#define K2_RW_4096_LAT 17000
#define K2_RW_508K_LAT 167000
#define K2_RW_2M_LAT 641000

#define K2_SW_512_LAT 14000
#define K2_SW_4096_LAT 16000
#define K2_SW_508K_LAT 166000
#define K2_SW_2M_LAT 643000

/** The initial value for the maximum in-flight latency */
#define K2_MAX_INFLIGHT_USECONDS (K2_RR_508K_LAT * 4)

#define k2_now() ktime_get_ns()

// Dynamic load level adjustment related
#define K2_ENABLE_LOAD_ADJUST 1
typedef u64 load_adjust_t;

#define K2_LOAD_ADJUST_WINDOW_LEN 100ULL
#define K2_LOAD_ADJUST_MULT 1000ULL
#define K2_LOAD_ADJUST_MULT_MIN 10ULL
#define K2_LOAD_ADJUST_MULT_MAX (K2_LOAD_ADJUST_MULT * 100ULL)
#define K2_LOAD_ADJUST_DEFAULT (K2_LOAD_ADJUST_WINDOW_LEN * K2_LOAD_ADJUST_MULT)
#define K2_LOAD_ADJUST_MAX (K2_LOAD_ADJUST_DEFAULT * K2_LOAD_ADJUST_MULT)
#define K2_LOAD_ADJUST_MIN 1ULL
static_assert(K2_LOAD_ADJUST_MAX < U64_MAX);

#define K2_ENABLE_ACCESS_PATTERN 1
// Assume a random io threshold of 16M based on the results from iocost
#define K2_RANDIO_THRESHOLD 16 << 20

// Starvation prevention
#define K2_MAX_QUEUE_WAIT 5000000000 // 5 seconds

extern bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
				   struct request **merged_request);

K2_LOG(u16 max_retries = 0;)

/* ===============================
 * ===== STRUCT DEFINITIONS ======
 * ============================ */

/**
 * @brief The type of a request
 * @details As we only treat READ and Writes, group all other request types in a separate category
 */
enum {
	K2_REQ_READ,
	K2_REQ_WRITE,
	K2_REQ_OTHER,
};

enum {
	K2_REQ_SEQ,
	K2_REQ_RAND,
};

enum {
	K2_REQ_512,
	K2_REQ_4096,
	K2_REQ_508K,
	K2_REQ_2M,
};

/**
 * @brief Global K2 data structure for one block device
 * @details This struct is initialized by the scheduler itself exactly once per device.
 *  Parallel modifications to this struct MUST ensure synchronous access provided via the k2_data::lock member
 */
struct k2_data {
	/**
     * @brief The number of requests currently dispatched to the device
     * @details Incremented in k2_dispatch(), decremented in k2_completed_request()
     */
	unsigned int inflight;

	/**
     * @brief The sum of estimated processing times of requests currently dispatched
     * @details Increased in k2_dispatch(), decresed in k2_completed_request()
     */
	latency_ns_t current_inflight_latency;

	/**
     * @brief The maximum sum of estimated latencies in flight at any time
     * @details The scheduler will stall requests, that would exceed this limit
     */
	latency_ns_t max_inflight_latency;

	/**
	 * @brief The sector, the last request was dispatched to
	 * @details This information is used to determine for new request, if a sequential or a random access is performed
	*/
	sector_t last_dispatched_sector;

	/**
	 * @brief The available block sizes for interpolation
	*/
	u64 block_sizes[K2_INTERPOLATION_VAL_COUNT];

	/**
	 * @brief Predefined request latencies
	 * @details Dimensions include
	 * 	* The operation type of the request (read/write)
	 *  * The access pattern of the request (sequential/random)
	 *  * The size of the request (as defined in block_sizes)
	*/
	latency_ns_t expected_latencies[2][2][K2_INTERPOLATION_VAL_COUNT];

	/**
	 * @brief The current load multiplier for read and write requests
	*/
	load_adjust_t load_mult[2];

	/**
	 * @brief Ringbuffer that keeps track of the latest K2_LOAD_ADJUST_WINDOW_LEN completed requests for read operations
	 * @details Each entry contains the ratio expected latency - real latency
	*/
	struct ringbuf last_read_ratios;

	/**
	 * @brief Ringbuffer that keeps track of the latest K2_LOAD_ADJUST_WINDOW_LEN completed requests for read operations
	 * @details Each entry contains the ratio expected latency - real latency
	*/
	struct ringbuf last_write_ratios;

	/**
	 * @brief Request queues (FIFO) for the realtime I/O priority class
	 * @details Offer separate request queues for each priority value of the realtime class
	*/
	struct list_head rt_reqs[IOPRIO_BE_NR];

	/**
	 * @brief Request queues (FIFO) for the best effort I/O priority class
	 * @details Offer a single request queue for all priority values of the best effort class.
	 * This queue also contains all request of all remaing io priority classes like IDLE.
	*/
	struct list_head be_reqs;

	/**
	 * @brief Timestamps of the latest dispatch for each realtime priority request queue
	 * @details Used for fairness aspect - Each queue gets to dispatch atleast once every K2_MAX_QUEUE_WAIT ns.
	 */
	ktime_t last_rt_queue_dispatches[IOPRIO_BE_NR];

	/**
	 * @brief Timestamps of the latest dispatch for the best effort request queue
	 * @details Used for fairness aspect - Each queue gets to dispatch atleast once every K2_MAX_QUEUE_WAIT ns.
	 */
	ktime_t last_be_queue_dispatch;

	/**
	 * @brief True if a regular realtime queue (the ones statically created in K2) got to dispatch last. False if a registered task queue got to dispatch last.
	 * @details This information is used to perform round robin arbitration for request queues of the different priority.
	*/
	bool scheduled_regular_rt_queue_last[IOPRIO_BE_NR];

	/**
	 * @brief True if the regular best effort queue (the one statically allocated in K2) got to dispatch last. False if a registered task queue got to dispatch last.
	 * @details This information is used to perform round robin arbitration for request queues of the different priority.
	*/
	bool scheduled_regular_be_queue_last;

	/**
	 * @brief Sector-ordered red-black tree for request merging
	*/
	struct rb_root sort_list[2];

	/**
	 * @brief Global lock for all operations that access this global K2 data struct
	*/
	spinlock_t lock;

	/**
	 * @brief List head to queue the K2 data for a specific gendisk (=block device) in the global K2 device struct used for interaction with userspace via IOCTL.
	*/
	struct list_head global_k2_list_element;

	/**
	 * @brief The request queue (=block device) this K2 data is managing.
	 */
	struct request_queue *rq;

	/**
	 * @brief The queue length for asynchronously issued requests.
	 * @details K2 limits the amount of asynchronously issued requests to avoid starvation of synchronous operations.
	*/
	u32 async_depth;

	/**
     * @brief Dynamically generated realtime I/O request queues
     * @details Use a list here and not a rb tree or hash table,
     *  as the number of special request queues is expected to be low
     */
	struct list_head rt_dynamic_rqs;

	/**
	 * @brief The timestamp of the next deadline for all registered tasks
	*/
	ktime_t next_dynamic_deadline;

	/**
	 * @brief The pid of the process of the next upcoming deadline for all registered tasks
	*/
	pid_t next_dynamic_deadline_pid;
};

/**
 * @brief A dynamically allocated request queue inside a k2_data structure
 * @details Used, whenever userspace registers a special io treatment of a process via ioctl
 *  Access __MUST__ always occur from a locked k2_data struct
 */
struct k2_dynamic_rt_rq {
	/**
     * @brief The process this request queue serves
     */
	pid_t pid;

	/**
     * @brief IO Priority group of the process - this can change dynamically!
     * @details If the userspace process changes its priority class, this value
     * will change also the scheduling priority of previously issued requests!
     */
	u8 prio_class;

	/**
     * @brief IO Priority level of the process - this can change dynamically!
     * @details If the userspace process changes its priority class, this value
     * will change also the scheduling priority of previously issued requests!
     */
	u8 prio_lvl;

	/**
     * @brief The interval, these requests will occur
     */
	latency_ns_t interval;

	/**
      * @brief Time point of the next expected occurrence of this request
      */
	timepoint_ns_t next_deadline;

	/**
      * @brief The latency introduced by the latest request issued by this task
      * @details The scheduler expects periodic realtime tasks to issue requests of the same processing time.
      */
	latency_ns_t last_request_latency;

	/**
	 * @brief The timestamp of the last dispatch for this queue
	 * @details Used for fairness aspect - Each queue gets to dispatch atleast once every K2_MAX_QUEUE_WAIT ns.
	*/
	ktime_t last_dispatch;

	/**
     * @brief The list of requests that are part of this request queue
     */
	struct list_head reqs;

	/**
     * @brief The list element to queue this object in the list of dynamic request queues of a k2 instance
     */
	struct list_head list;
};

/* ===============================
 * ===== FUNCTION PROTOTYPES =====
 * ============================ */

static int k2_add_dynamic_rt_rq(struct k2_data *k2d, pid_t pid,
				latency_ns_t interval);
static int k2_del_dynamic_rt_rq(struct k2_data *k2d, pid_t pid);
static int k2_del_all_dynamic_rt_rq(struct k2_data *k2d);
static struct k2_data *k2_get_k2d_by_disk(const char *disk_name);

/* =========================
 * ===== SYSFS RELATED =====
 * ====================== */

ssize_t k2_max_inflight_latency_show(struct elevator_queue *eq, char *s)
{
	struct k2_data *k2d = eq->elevator_data;

	return (sprintf(s, "%lld\n", k2d->max_inflight_latency));
}

ssize_t k2_max_inflight_latency_set(struct elevator_queue *eq, const char *s,
				    size_t size)
{
	struct k2_data *k2d = eq->elevator_data;
	unsigned int new_max;
	unsigned long flags;

	if (kstrtouint(s, 10, &new_max) >= 0) {
		spin_lock_irqsave(&k2d->lock, flags);
		k2d->max_inflight_latency = new_max;
		spin_unlock_irqrestore(&k2d->lock, flags);
		printk(KERN_INFO "k2: max_inflight set to %lld\n",
		       k2d->max_inflight_latency);

		return (size);
	}

	/* error, leave max_inflight as is */
	return (size);
}

ssize_t current_inflight_latency_show(struct elevator_queue *eq, char *s)
{
	struct k2_data *k2d = eq->elevator_data;
	return (sprintf(s, "%lld\n", k2d->current_inflight_latency));
}

ssize_t current_inflight_show(struct elevator_queue *eq, char *s)
{
	struct k2_data *k2d = eq->elevator_data;
	return (sprintf(s, "%u\n", k2d->inflight));
}

static struct elv_fs_entry k2_attrs[] = {
	__ATTR_RO(current_inflight),
	__ATTR(max_inflight_latency, S_IRUGO | S_IWUSR,
	       k2_max_inflight_latency_show, k2_max_inflight_latency_set),
	__ATTR_RO(current_inflight_latency), __ATTR_NULL
};

/* ===============
 * ==== IOCTL ====
 * ============ */

/**
 * @See https://static.lwn.net/images/pdf/LDD3/ch03.pdf
 */
#define K2_DEVICE_NAME "k2-iosched"
#define K2_NUMBER_DEVICES 1

/**
 * @brief Global k2 dev instance
 */
struct k2_dev {
	/**
     * @brief Character device handle
     * @details Required for registration of device
     */
	struct cdev cdev;

	/**
     * @brief Device node handle for registration on /dev
     */
	struct device *device;

	/**
     * @brief List of running instances of the scheduler per gendisk
     */
	struct list_head k2_instances;

	spinlock_t lock;
};

/**
 * @brief Global device pointer for ioctl interaction
 * @details Always check for NULL, make sure to deallocate on module cleanup
 */
static struct k2_dev *k2_global_k2_dev = NULL;

static int k2_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int k2_dev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

/**
 * @brief Entry point for ioctl requests
 */
static long k2_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	// struct inode *inode = file_inode(file);

	void __user *argp = (void __user *)arg;
	unsigned long ret = 0;
	struct k2_ioctl ioctl;
	char dev[K2_IOCTL_BLK_DEV_NAME_LENGTH];
	struct list_head *list_element;
	struct k2_data *k2d;
	char string_param[K2_IOCTL_CHAR_PARAM_LENGTH];
	char *separator = ";";

	memset(string_param, 0, K2_IOCTL_CHAR_PARAM_LENGTH);
	memset(dev, 0, K2_IOCTL_BLK_DEV_NAME_LENGTH);
	memset(&ioctl, 0, sizeof(ioctl));

	switch (cmd) {
	case K2_IOC_GET_VERSION:
		ret = copy_from_user(&ioctl, argp, sizeof(struct k2_ioctl));
		if (ret) {
			break;
		}
		ret = copy_to_user(
			ioctl.string_param, THIS_MODULE->version,
			min(strlen(THIS_MODULE->version),
			    (unsigned long)K2_IOCTL_CHAR_PARAM_LENGTH));
		break;

	case K2_IOC_REGISTER_PERIODIC_TASK:
		ret = copy_from_user(&ioctl, argp, sizeof(ioctl));
		if (ret) {
			break;
		}
		ret = copy_from_user(dev, ioctl.blk_dev,
				     K2_IOCTL_BLK_DEV_NAME_LENGTH);
		if (ret) {
			break;
		}
		printk(KERN_INFO
		       "k2: Requesting periodic task with pid %u and interval of %lld ns for %s\n",
		       ioctl.task_pid, ioctl.interval_ns, dev);
		k2d = k2_get_k2d_by_disk(dev);
		if (NULL == k2d) {
			return -ENOENT;
		}
		ret = k2_add_dynamic_rt_rq(k2d, ioctl.task_pid,
					   ioctl.interval_ns);
		if (ret) {
			break;
		}
		printk(KERN_INFO
		       "k2: Registered periodic task with pid %d on %s\n",
		       ioctl.task_pid, dev);
		break;

	case K2_IOC_UNREGISTER_PERIODIC_TASK:
		ret = copy_from_user(&ioctl, argp, sizeof(ioctl));
		if (ret) {
			break;
		}
		ret = copy_from_user(dev, ioctl.blk_dev,
				     K2_IOCTL_BLK_DEV_NAME_LENGTH);
		if (ret) {
			break;
		}
		printk(KERN_INFO
		       "k2: Requesting unregistration of periodic task with pid %u for %s\n",
		       ioctl.task_pid, dev);

		k2d = k2_get_k2d_by_disk(dev);
		if (NULL == k2d) {
			return -ENOENT;
		}
		ret = k2_del_dynamic_rt_rq(k2d, ioctl.task_pid);
		if (ret) {
			break;
		}
		printk(KERN_INFO
		       "k2: Unregistered periodic task with pid %d on %s\n",
		       ioctl.task_pid, dev);
		break;

	case K2_IOC_UNREGISTER_ALL_PERIODIC_TASKS:
		ret = copy_from_user(&ioctl, argp, sizeof(ioctl));
		if (ret) {
			break;
		}
		ret = copy_from_user(dev, ioctl.blk_dev,
				     K2_IOCTL_BLK_DEV_NAME_LENGTH);
		if (ret) {
			break;
		}
		printk(KERN_INFO
		       "k2: Requesting unregistration of all periodic tasks for %s\n",
		       dev);

		k2d = k2_get_k2d_by_disk(dev);
		if (NULL == k2d) {
			return -ENOENT;
		}
		ret = k2_del_all_dynamic_rt_rq(k2d);
		K2_LOG(max_retries = 0;)
		if (ret) {
			break;
		}
		printk(KERN_INFO "k2: Unregistered all periodic tasks on %s\n",
		       dev);
		break;

	case K2_IOC_GET_DEVICES:
		ret = copy_from_user(&ioctl, argp, sizeof(struct k2_ioctl));
		if (ret) {
			break;
		}
		if (list_empty(&k2_global_k2_dev->k2_instances)) {
			break;
		}
		list_element = k2_global_k2_dev->k2_instances.next;
		while (list_element != &k2_global_k2_dev->k2_instances) {
			k2d = list_entry(list_element, struct k2_data,
					 global_k2_list_element);
			printk(KERN_INFO "k2: k2 is active on /dev/%s\n",
			       k2d->rq->disk->disk_name);
			if (strlen(string_param) +
				    strlen(k2d->rq->disk->disk_name) +
				    strlen(separator) <
			    K2_IOCTL_CHAR_PARAM_LENGTH) {
				strcpy(string_param + strlen(string_param),
				       separator);
				memcpy(string_param + strlen(string_param),
				       k2d->rq->disk->disk_name,
				       strlen(k2d->rq->disk->disk_name));
			}
			if (list_element->next) {
				list_element = list_element->next;
			}
		}
		printk(KERN_INFO "k2: k2 is active on %s\n", string_param);

		ret = copy_to_user(ioctl.string_param, string_param,
				   K2_IOCTL_CHAR_PARAM_LENGTH);

		break;

	default:
		return -EINVAL;
	}
	return (long)ret;
}

static const struct file_operations k2_dev_fops = {
	.owner = THIS_MODULE,
	.llseek = noop_llseek, // As in btrfs driver registration
	.read = NULL,
	.write = NULL,
	.open = k2_dev_open,
	.release = k2_dev_release,
	.unlocked_ioctl = k2_dev_ioctl,
	.compat_ioctl =
		compat_ptr_ioctl, // https://docs.kernel.org/driver-api/ioctl.html#bit-compat-mode
};

static void k2_close_dev(struct k2_dev *device)
{
	if (device) {
		if (device->device) {
			struct class *k2_class = device->device->class;
			device_destroy(k2_class, device->cdev.dev);
			class_destroy(k2_class);
		}
		unregister_chrdev_region(device->cdev.dev, 1);
		cdev_del(&device->cdev);
		unregister_chrdev_region(device->cdev.dev, K2_NUMBER_DEVICES);
		kfree(device);
	}
	device = NULL;
	k2_global_k2_dev = NULL;
	printk(KERN_INFO "k2: Unregistered device node: /dev/%s\n",
	       K2_DEVICE_NAME);
}

static int k2_init_dev(void)
{
	dev_t device_id;
	int error = 0;
	struct class *k2_class = NULL;
	struct device *k2_device = NULL;
	struct k2_dev *dev;

	dev = kzalloc(sizeof(struct k2_dev), GFP_KERNEL);
	if (NULL == dev) {
		printk(KERN_ERR
		       "k2: could not allocate device: device struct kzalloc() failed\n");
		return -ENOMEM;
	}

	error = alloc_chrdev_region(&device_id, 0, K2_NUMBER_DEVICES,
				    K2_DEVICE_NAME);
	if (error < 0) {
		printk(KERN_ERR
		       "k2: could not allocate device: alloc_chrdev_region() failed: %d\n",
		       error);
		goto abort;
	}

	spin_lock_init(&dev->lock);

	cdev_init(&dev->cdev, &k2_dev_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &k2_dev_fops;
	error = cdev_add(&dev->cdev, device_id, 1);
	if (error) {
		printk(KERN_ERR
		       "k2: could not allocate device: cdev_add() failed\n");
		goto abort;
	}

	printk(KERN_INFO
	       "k2: Initialized device with Major device number: %d and "
	       "Minor device number: %d\n",
	       MAJOR(dev->cdev.dev), MINOR(dev->cdev.dev));

	k2_class = class_create(THIS_MODULE, K2_DEVICE_NAME);
	if (IS_ERR(k2_class)) {
		printk(KERN_ERR
		       "k2: could not allocate device: class_create() failed\n");
		error = -EEXIST; // I do not know what else to put here :/
		goto abort;
	}

	k2_device =
		device_create(k2_class, NULL, device_id, NULL, K2_DEVICE_NAME);
	if (IS_ERR(k2_device)) {
		printk(KERN_ERR
		       "k2: could not allocate device: device_create() failed\n");
		class_destroy(k2_class);
		error = -EEXIST; // I do not know what else to put here :/
		goto abort;
	}

	INIT_LIST_HEAD(&dev->k2_instances);
	dev->device = k2_device;

	k2_global_k2_dev = dev;
	printk(KERN_INFO "k2: Initialized device node: /dev/%s\n",
	       K2_DEVICE_NAME);

	return 0;

abort:
	k2_close_dev(dev);
	return error;
}

/* =============================
 * ==== K2 helper functions ====
 * ========================== */

static const char *k2_req_type_names[] = {
	[K2_REQ_READ] = "READ",
	[K2_REQ_WRITE] = "WRITE",
	[K2_REQ_OTHER] = "OTHER",
};

/**
 * @brief Get the access type of a request
 */
static inline unsigned int k2_req_type(struct request *rq)
{
	switch (req_op(rq) & REQ_OP_MASK) {
	case REQ_OP_READ:
		return K2_REQ_READ;
	case REQ_OP_WRITE:
		return K2_REQ_WRITE;
	default:
		return K2_REQ_OTHER;
	}
}

/**
 * @brief Check, if the scheduler has attached any data to the request
 * @details This is most likely the case because the request is a flush request
 * Do not try to read or write to attached elv data, if this is the case!
 */
static inline bool k2_rq_is_managed_by_k2(struct request *rq)
{
	return rq->rq_flags & RQF_ELVPRIV;
}

static inline struct rb_root *k2_rb_root(struct k2_data *k2d,
					 struct request *rq)
{
	return &k2d->sort_list[rq_data_dir(rq)];
}

static void k2_add_rq_rb(struct k2_data *k2d, struct request *rq)
{
	struct rb_root *root = k2_rb_root(k2d, rq);

	elv_rb_add(root, rq);
}

static inline void k2_del_rq_rb(struct k2_data *k2d, struct request *rq)
{
	elv_rb_del(k2_rb_root(k2d, rq), rq);
}

/**
 * @brief Get the io prio of a task by either its ionice or regular nice value
 */
static void k2_ioprio_from_task(int *class, int *value)
{
	if (current->io_context == NULL ||
	    !ioprio_valid(current->io_context->ioprio)) {
		*class = task_nice_ioclass(current);
		*value = IOPRIO_NORM;
	} else {
		*class = IOPRIO_PRIO_CLASS(current->io_context->ioprio);
		*value = IOPRIO_PRIO_DATA(current->io_context->ioprio);
	}
}

/**
 * @brief Check if the scheduler has possibly work to do.
 * @details This does not mean, it will actually dispatch a request on the next k2_dispatch_request() invokation.
 * Further restrictions are applied in the dispatch function itself.
 */
static bool _k2_has_work(struct k2_data *k2d)
{
	unsigned int i;
	struct list_head *list_elem;
	struct k2_dynamic_rt_rq *rt_rqs;
	ktime_t now = k2_now();

	// If there is a dynamic queue pending, allow running the queues
	if (now >= k2d->next_dynamic_deadline) {
		K2_LOG(printk("Allow registered %lld %lld %lld\n", now,
			      k2d->next_dynamic_deadline,
			      now - k2d->next_dynamic_deadline);)
		return true;
	}

	// If the limit of concurrent request latencies is reached and there are no more "free" requests left, abort
	if (k2d->current_inflight_latency >= k2d->max_inflight_latency &&
	    k2d->inflight > K2_MINIMUM_COHERENT_REQUEST_COUNT) {
		return (false);
	}

	// Check all software queues
	if (!list_empty(&k2d->be_reqs)) {
		K2_LOG(printk(KERN_INFO "k2: CALL has_work software queue \n"));
		return (true);
	}

	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (!list_empty(&k2d->rt_reqs[i])) {
			K2_LOG(printk(
				KERN_INFO
				"k2: CALL has_work software queue rt \n"));
			return (true);
		}
	}

	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each (list_elem, &k2d->rt_dynamic_rqs) {
			rt_rqs = list_entry(list_elem, struct k2_dynamic_rt_rq,
					    list);
			if (!list_empty(&rt_rqs->reqs)) {
				K2_LOG(printk(
					KERN_INFO
					"k2: CALL has_work %d dynamic rt \n",
					rt_rqs->pid));
				return true;
			}
		}
	}

	return (false);
}

/**
 * @brief Remove a request from the scheduler internal rb tree for back merges.
 */
static void k2_remove_request(struct request_queue *q, struct request *r)
{
	struct k2_data *k2d = q->elevator->elevator_data;

	list_del_init(&r->queuelist);

	/*
     * During an insert merge r might have not been added to the rb-tree yet
     */
	if (!RB_EMPTY_NODE(&r->rb_node))
		k2_del_rq_rb(k2d, r);

	elv_rqhash_del(q, r);
	if (q->last_merge == r)
		q->last_merge = NULL;
}

/**
 * @brief Linearly interpolate the latency of a request based on its size (value) between two predefined values
 * @param val The value to get the interpolated latency for
 * @param lower_val The next smaller value with a associated latency
 * @param upper_val The next higher value with a assocuated latency
 * @param lower_lat The latency associated with @param lower_val
 * @param upper_lat The latency associated with @param upper_val
 * @return The interpolated latency for the requestes value
 */
static latency_ns_t k2_linear_interpolation(const u32 val, const u32 lower_val,
					    const u32 upper_val,
					    const latency_ns_t lower_lat,
					    const latency_ns_t upper_lat)
{
	const u32 diff_val = upper_val - lower_val;
	const latency_ns_t diff_lat = ktime_sub(upper_lat, lower_lat);
	const u32 offset_val = val - lower_val;
	const u32 value_percentage = 100 * offset_val / diff_val;
	return lower_lat + diff_lat * value_percentage / 100;
}

/**
 * @brief Perform dynamic device load adoptions for expected request latencies
 * @details K2 keeps a history of the ratios of expected to real latencies of the latest K2_LOAD_ADJUST_WINDOW_LEN requests that where dispatched to the device.
 * Once a request is finished, the new ratio is inserted to the ringbuffer, while the oldest one is released, both modifying the global device load multiplier.
 * @param mult The current load multiplier
 * @param rb The ring buffer associated with the load multiplier
 * @param estimated_latency The real latency of the request to register
 * @param real_latency  The previously estimated latency of the request to register
 */
static void k2_load_adjust_sliding_window(load_adjust_t *mult,
					  struct ringbuf *rb,
					  latency_ns_t estimated_latency,
					  latency_ns_t real_latency)
{
	load_adjust_t last_ratio;
	K2_LOG(load_adjust_t old_mult = *mult;)
	load_adjust_t new_ratio =
		real_latency * K2_LOAD_ADJUST_MULT / estimated_latency;
	new_ratio = clamp_val(new_ratio, K2_LOAD_ADJUST_MULT_MIN,
			      K2_LOAD_ADJUST_MULT_MAX);

	*mult += new_ratio;

	// Undo operation that is no longer valid
	ringbuf_pushback(rb, new_ratio, last_ratio, load_adjust_t);
	*mult -= last_ratio;
}

static u32 k2_get_rq_bytes(struct request *rq);
/**
 * @brief Determine the expected latency of a request
 * @details This estimation is stateful and depends on the current load and access situation of the device,
 * call only from k2_dispatch_request()
 */
static latency_ns_t k2_expected_request_latency(struct k2_data *k2d,
						struct request *rq)
{
	const unsigned int rq_size = k2_get_rq_bytes(rq);

	// Requests that are neither write nor read are not taken into account
	latency_ns_t rq_lat = 0;
	unsigned type = k2_req_type(rq);
	int access_pattern = K2_REQ_RAND;
	u64 bytes_diff = 0;

	if (K2_REQ_OTHER == type) {
		K2_LOG(printk(KERN_INFO "k2: Request is misc: %u\n",
			      rq->cmd_flags & REQ_OP_MASK));
		goto end;
	}

#if K2_ENABLE_ACCESS_PATTERN == 1
	bytes_diff = abs(blk_rq_pos(rq) - k2d->last_dispatched_sector)
		     << SECTOR_SHIFT;

	if (bytes_diff < K2_RANDIO_THRESHOLD) {
		access_pattern = K2_REQ_SEQ;
	}
	K2_LOG(printk(KERN_INFO "k2: Access is random: %d\n",
		      access_pattern == K2_REQ_RAND));
#endif

	K2_LOG(printk(KERN_INFO "k2: Request size: %u (%uk), type: %s\n", rq_size,
		      rq_size >> 10, k2_req_type_names[type]));

	if (rq_size <= k2d->block_sizes[K2_REQ_512]) {
		rq_lat = k2d->expected_latencies[type][access_pattern]
						[K2_REQ_512];
	} else if (rq_size <= k2d->block_sizes[K2_REQ_4096]) {
		rq_lat = k2_linear_interpolation(
			rq_size, k2d->block_sizes[K2_REQ_512],
			k2d->block_sizes[K2_REQ_4096],
			k2d->expected_latencies[type][access_pattern]
					       [K2_REQ_512],
			k2d->expected_latencies[type][access_pattern]
					       [K2_REQ_4096]);
	} else if (rq_size <= k2d->block_sizes[K2_REQ_508K]) {
		rq_lat = k2_linear_interpolation(
			rq_size, k2d->block_sizes[K2_REQ_4096],
			k2d->block_sizes[K2_REQ_508K],
			k2d->expected_latencies[type][access_pattern]
					       [K2_REQ_4096],
			k2d->expected_latencies[type][access_pattern]
					       [K2_REQ_508K]);
	} else if (rq_size < k2d->block_sizes[K2_REQ_2M]) {
		rq_lat = k2_linear_interpolation(
			rq_size, k2d->block_sizes[K2_REQ_508K],
			k2d->block_sizes[K2_REQ_2M],
			k2d->expected_latencies[type][access_pattern]
					       [K2_REQ_508K],
			k2d->expected_latencies[type][access_pattern]
					       [K2_REQ_2M]);
	} else {
		rq_lat =
			k2d->expected_latencies[type][access_pattern][K2_REQ_2M];
	}

#if K2_ENABLE_LOAD_ADJUST == 1
	rq_lat = (load_adjust_t)rq_lat * k2d->load_mult[type] /
		 K2_LOAD_ADJUST_DEFAULT;
#endif

end:
	K2_LOG(printk(KERN_INFO "k2: Expected introduced latency: %lld\n",
		      rq_lat));
	return rq_lat;

legacy:
	// Assume behaviour that mimics the legacy k2-8 behaviour
	return K2_MAX_INFLIGHT_USECONDS / 8;
}

/**
 * @brief Set the estimated latency introduced by a certain request
 * @details For assigning additional data to each request, the kernel offers certain pointers in the request struct.
 * Apply some magic casting and be done with it.
 * */
static inline void k2_set_rq_data(struct request *rq, latency_ns_t rq_lat,
				  pid_t pid)
{
	rq->elv.priv[0] = (void *)(latency_ns_t)rq_lat;

	// As pointer sizes are expected to be 64 bit wide, we can use it to store 2 32 bit values:
	// The pid, and later on, the number of attempts to schedule the request
	// 16 RTC Attempts | 16 Reserved | 32 PID
	rq->elv.priv[1] = (void *)((u64)NULL | (s32)pid);
}

static inline void k2_set_rq_pid(struct request *rq, pid_t pid)
{
	rq->elv.priv[1] = (void *)((u64)NULL | (s32)pid);
}

static inline void k2_set_rq_latency(struct request *rq, latency_ns_t lat)
{
	rq->elv.priv[0] = (void *)(latency_ns_t)lat;
}

/**
 * @brief Get the estimated latency introduced by a certain request
 * @details For assigning additional data to each request, the kernel offers certain pointers in the request struct
 * Apply some magic casting and be done with it.
 * */
static inline latency_ns_t k2_get_rq_latency(struct request *rq)
{
	return (latency_ns_t)rq->elv.priv[0];
}

static inline u32 k2_get_rq_bytes(struct request *rq)
{
	return blk_rq_payload_bytes(rq);
}

static inline pid_t k2_get_rq_pid(struct request *rq)
{
	return (pid_t)(uintptr_t)rq->elv.priv[1];
}

static inline u16 k2_get_rq_schedule_attempts_rt_constraint(struct request *rq)
{
	return (u16)((u64)(uintptr_t)rq->elv.priv[1] >> 48);
}

static inline void k2_set_rq_attempts_rt_constrain(struct request *rq, u16 new)
{
	rq->elv.priv[1] =
		(void *)(((u64)rq->elv.priv[1] & 0x0000FFFFFFFFFFFFLL) |
			 (((u64) new) << 48));
}

static inline void k2_increment_rq_attempts_rt_constrain(struct request *rq)
{
	u16 cur = k2_get_rq_schedule_attempts_rt_constraint(rq);
	k2_set_rq_attempts_rt_constrain(rq, cur + 1);
}

/**
 * @brief Add a request to the calculation of globally in-flight requests
 * @details This function has to be called from a locked context, as concurrent
 * accesses to the global struct would tamper with the result
 * @param k2d The global k2_data struct
 * @param rq The request to process
 */
static inline void k2_add_latency(struct k2_data *k2d, struct request *rq)
{
	const unsigned int count = k2d->inflight + 1;
	const latency_ns_t lat =
		ktime_add(k2d->current_inflight_latency, k2_get_rq_latency(rq));

	K2_LOG(printk(KERN_DEBUG
		      "k2: Added: current inflight %u, current_latency %lld\n",
		      count, lat));

	k2d->inflight = count;
	k2d->current_inflight_latency = lat;
}

/**
 * @brief Remove a request from the calculation of globally in-flight requests
 * @details This function has to be called from a locked context, as concurrent
 * accesses to the global struct would tamper with the result
 * @param k2d The global k2_data struct
 * @param rq The request to process
 */
static inline void k2_remove_latency(struct k2_data *k2d, struct request *rq)
{
	unsigned int count;
	latency_ns_t lat;
	latency_ns_t rq_lat;

	rq_lat = k2_get_rq_latency(rq);
	if (rq_lat < 0) {
		printk(KERN_ERR
		       "k2: Encountered negative request latency, aborting k2_remove_latency()\n");
		dump_stack();
		return;
	}

	count = k2d->inflight;
	lat = k2d->current_inflight_latency;

	if (count >= 1) {
		count--;
	}

	if (lat > rq_lat) {
		lat -= rq_lat;
	} else {
		lat = 0;
	}

	K2_LOG(printk(KERN_DEBUG
		      "k2: Removed: current inflight %u, current_latency %lld\n",
		      count, lat));

	k2d->inflight = count;
	k2d->current_inflight_latency = lat;
}

/**
 * @brief Determine, weather a request can currently be dispatched with respect to the global scheduling limitations
 */
static inline bool k2_does_request_fit(struct k2_data *k2d, struct request *rq)
{
	bool does_fit;

	// Do not deadlock when request time exceeds maximum inflight latency
	if (k2d->inflight <= K2_MINIMUM_COHERENT_REQUEST_COUNT) {
		K2_LOG(printk(
			KERN_INFO
			"k2: Queue length is lower than throttling threshold, request dispatch accepted!\n"));
		return true;
	}

	if (k2d->max_inflight_latency > k2d->current_inflight_latency) {
		does_fit = k2_get_rq_latency(rq) <=
			   k2d->max_inflight_latency -
				   k2d->current_inflight_latency;
	} else {
		// Queue limit already exceeded
		does_fit = false;
	}

	if (!does_fit) {
		K2_LOG(printk(
			KERN_INFO
			"k2: Request dispatch rejected, queue limit would be exceeded!\n"));
	} else {
		K2_LOG(printk(KERN_INFO "k2: Request dispatch accepted!\n"));
	}

	return does_fit;
}

/**
 * @brief Determine if a request can be dispatched with respect to the next upcoming registered realtime task and global scheduling decisions
 */
static inline bool
k2_does_request_fit_check_registered_queues(struct k2_data *k2d,
					    struct request *rq,
					    struct k2_dynamic_rt_rq *rt_rqs)
{
	bool does_fit;
	if (k2d->inflight <= K2_MINIMUM_COHERENT_REQUEST_COUNT) {
		// Do not deadlock when request time exceeds maximum inflight latency
		K2_LOG(printk(
			KERN_INFO
			"k2: Queue length is lower than throttling threshold, request dispatch accepted!\n"));
		return true;
	}

	if (NULL != rt_rqs) {
		// There are no rt queues
		if (k2_get_rq_latency(rq) + k2_now() <= rt_rqs->next_deadline) {
			// The new request will be completed before the next deadline
			goto regular_constraints;
		}
		if (k2d->current_inflight_latency + k2_get_rq_latency(rq) +
			    rt_rqs->last_request_latency <=
		    k2d->max_inflight_latency) {
			// The overhead introduced by the new request does not interfere performance goals registered realtime tasks
			goto regular_constraints;
		}
		K2_LOG(printk("k2: has work: deadline\n");)

		// The following code snipped was a quick workaround, where normal, non registered low prio
		// requests would lead to a stall of the processing kernel thread, as they would never be scheduled,
		// When their estimated processing time would exceed the next deadline constraint of a registered task
		// even when there were no outstanding requests
#if 0
        if (list_empty(&rt_rqs->reqs)) {
	    return true;
	}
#endif
#if 1
		// The new solution is to define a maximum number of retries for a request, that was denied because of the next rt deadline
		if (k2_get_rq_schedule_attempts_rt_constraint(rq) >=
		    K2_REQUEST_RETRY_COUNT_RT_CONSTRAINT) {
			goto regular_constraints;
		}
		k2_increment_rq_attempts_rt_constrain(rq);
		return false;
	}
#endif

regular_constraints:
	if (k2d->max_inflight_latency > k2d->current_inflight_latency) {
		does_fit = k2_get_rq_latency(rq) <=
			   k2d->max_inflight_latency -
				   k2d->current_inflight_latency;
	} else {
		// Queue limit already exceeded
		does_fit = false;
	}

	if (!does_fit) {
		K2_LOG(printk(
			KERN_INFO
			"k2: Request dispatch rejected, queue limit would be exceeded!\n"));
	} else {
		K2_LOG(printk(KERN_INFO "k2: Request dispatch accepted!\n"));
	}

	return does_fit;
}

/**
 * @brief Add a new dynamic queue for a registered task
 * @param k2d The k2d this queue belongs to
 * @param pid The pid of the registered task
 * @param interval The request submission interval as registered by userspace
 * @return 0 on success, else error code
 */
static int k2_add_dynamic_rt_rq(struct k2_data *k2d, pid_t pid,
				latency_ns_t interval)
{
	struct k2_dynamic_rt_rq *rq;
	struct list_head *list_elem;
	unsigned long flags;
	int error = 0;

	// TODO: Avoid busy waiting here?
	spin_lock_irqsave(&k2d->lock, flags);

	// Check if PID is already assigned
	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each (list_elem, &k2d->rt_dynamic_rqs) {
			rq = list_entry(list_elem, struct k2_dynamic_rt_rq,
					list);
			if (rq->pid == pid) {
				error = -EEXIST;
				goto finally;
			}
		}
	}

	// TODO: Is this memory handling correct?
	rq = kzalloc_node(sizeof(struct k2_dynamic_rt_rq), GFP_KERNEL,
			  k2d->rq->node);
	if (NULL == rq) {
		kobject_put(&k2d->rq->elevator->kobj);
		error = -ENOMEM;
		goto finally;
	}

	INIT_LIST_HEAD(&rq->list);
	INIT_LIST_HEAD(&rq->reqs);
	rq->pid = pid;
	rq->interval = interval;
	// After registration, there is no synchronisation between requests, this first occurs, when the first actual request occurs
	rq->next_deadline = 0;
	// After registration, there is no knowledge of the introduced latency by the request, this is set after the first request has completed
	rq->last_request_latency = 0;

	rq->last_dispatch = 0;
	// Assume the default best effort scheduling class
	// This will be set correctly when the first request is inserted in the scheduler
	rq->prio_class = IOPRIO_CLASS_BE;
	rq->prio_lvl = IOPRIO_BE_NORM;

	// Register this request queue
	list_add_tail(&rq->list, &k2d->rt_dynamic_rqs);

finally:
	spin_unlock_irqrestore(&k2d->lock, flags);
	return error;
}

/**
 * @brief Delete an existing dynamic queue for a registered task
 * @param k2d The k2d this queue belongs to
 * @param pid The pid of the registered task
 * @return 0 on success, else error code
 */
static int k2_del_dynamic_rt_rq(struct k2_data *k2d, pid_t pid)
{
	struct k2_dynamic_rt_rq *rqs;
	struct list_head *list_elem;
	struct list_head *tmp;
	int error = 0;
	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);

	// Check if PID is already assigned
	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each_safe (list_elem, tmp, &k2d->rt_dynamic_rqs) {
			rqs = list_entry(list_elem, struct k2_dynamic_rt_rq,
					 list);
			if (rqs->pid == pid) {
				list_del(list_elem);
				kfree(rqs);
				k2d->next_dynamic_deadline = S64_MAX;
				k2d->next_dynamic_deadline_pid = -1;
				goto finally;
			}
		}
	}

	error = -ENOENT;

finally:
	spin_unlock_irqrestore(&k2d->lock, flags);
	return error;
}

/**
 * @brief Delete all dynamic queues for a device
 * @param k2d The k2d of the device
 * @return 0 on success, else error code
 */
static int k2_del_all_dynamic_rt_rq(struct k2_data *k2d)
{
	struct k2_dynamic_rt_rq *rqs;
	struct list_head *list_elem;
	struct list_head *tmp;
	int error = 0;
	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);

	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each_safe (list_elem, tmp, &k2d->rt_dynamic_rqs) {
			rqs = list_entry(list_elem, struct k2_dynamic_rt_rq,
					 list);
			// TODO: How to handle requests still in software queues?
			//  Do nothing like in static queues? Are those lost?
			//  What about the associated kernel memory buffer?
			printk(KERN_INFO
			       "k2: Deleting realtime request queue for pid %d on %s\n",
			       rqs->pid, k2d->rq->disk->disk_name);
			list_del(list_elem);
			kfree(rqs);
		}
		k2d->next_dynamic_deadline = S64_MAX;
		k2d->next_dynamic_deadline_pid = -1;
	}

	spin_unlock_irqrestore(&k2d->lock, flags);
	return error;
}

/**
 * @brief Get the k2_data structure active on a certain disk by name
 * @param disk_name The name of the disk as listed in e.g. /dev/nvme0n1, omit the /dev/ part
 * @return Pointer to the according k2_data if exists, else NULL
 */
static struct k2_data *k2_get_k2d_by_disk(const char *disk_name)
{
	unsigned long flags;
	struct list_head *list_elem;
	struct k2_data *ret = NULL;
	struct k2_data *tmp;

	if (!k2_global_k2_dev) {
		return NULL;
	}

	spin_lock_irqsave(&k2_global_k2_dev->lock, flags);

	if (list_empty(&k2_global_k2_dev->k2_instances)) {
		goto finally;
	}
	list_for_each (list_elem, &k2_global_k2_dev->k2_instances) {
		// TODO: Lock here? Should not be required, as this value should not change.
		tmp = list_entry(list_elem, struct k2_data,
				 global_k2_list_element);
		if (strcmp(disk_name, tmp->rq->disk->disk_name) == 0) {
			ret = tmp;
			goto finally;
		}
	}

finally:
	spin_unlock_irqrestore(&k2_global_k2_dev->lock, flags);
	return ret;
}

/* ==============================
 * ===== ELEVATOR CALLBACKS =====
 * ============================*/

static int k2_init_sched(struct request_queue *rq, struct elevator_type *et)
{
	struct k2_data *k2d;
	struct elevator_queue *eq;
	unsigned i;
	struct ringbuf *rb;
	void *ringbuf_iter;

	eq = elevator_alloc(rq, et);
	if (eq == NULL)
		return (-ENOMEM);

	/* allocate scheduler data from mem pool of request queue */
	k2d = kzalloc_node(sizeof(struct k2_data), GFP_KERNEL, rq->node);
	if (k2d == NULL) {
		kobject_put(&eq->kobj);
		return (-ENOMEM);
	}
	eq->elevator_data = k2d;

	k2d->inflight = 0;
	k2d->current_inflight_latency = 0;
	k2d->max_inflight_latency = K2_MAX_INFLIGHT_USECONDS;
	for (i = 0; i < IOPRIO_BE_NR; i++) {
		INIT_LIST_HEAD(&k2d->rt_reqs[i]);
		k2d->last_rt_queue_dispatches[i] = 0;
		k2d->scheduled_regular_rt_queue_last[i] = true;
	}

	INIT_LIST_HEAD(&k2d->be_reqs);
	k2d->last_be_queue_dispatch = 0;
	k2d->scheduled_regular_be_queue_last = true;

	k2d->sort_list[READ] = RB_ROOT;
	k2d->sort_list[WRITE] = RB_ROOT;

	// The first access will always be a random access
	k2d->last_dispatched_sector = U64_MAX;

	k2d->block_sizes[K2_REQ_512] = 512;
	k2d->block_sizes[K2_REQ_4096] = 4096;
	k2d->block_sizes[K2_REQ_508K] = 508 * 1024;
	k2d->block_sizes[K2_REQ_2M] = 2048 * 1024;

	k2d->expected_latencies[K2_REQ_READ][K2_REQ_RAND][K2_REQ_512] =
		K2_RR_512_LAT;
	k2d->expected_latencies[K2_REQ_READ][K2_REQ_RAND][K2_REQ_4096] =
		K2_RR_4096_LAT;
	k2d->expected_latencies[K2_REQ_READ][K2_REQ_RAND][K2_REQ_508K] =
		K2_RR_508K_LAT;
	k2d->expected_latencies[K2_REQ_READ][K2_REQ_RAND][K2_REQ_2M] =
		K2_RR_2M_LAT;

	k2d->expected_latencies[K2_REQ_READ][K2_REQ_SEQ][K2_REQ_512] =
		K2_SR_512_LAT;
	k2d->expected_latencies[K2_REQ_READ][K2_REQ_SEQ][K2_REQ_4096] =
		K2_SR_4096_LAT;
	k2d->expected_latencies[K2_REQ_READ][K2_REQ_SEQ][K2_REQ_508K] =
		K2_SR_508K_LAT;
	k2d->expected_latencies[K2_REQ_READ][K2_REQ_SEQ][K2_REQ_2M] =
		K2_SR_2M_LAT;

	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_RAND][K2_REQ_512] =
		K2_RW_512_LAT;
	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_RAND][K2_REQ_4096] =
		K2_RW_4096_LAT;
	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_RAND][K2_REQ_508K] =
		K2_RW_508K_LAT;
	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_RAND][K2_REQ_2M] =
		K2_RW_2M_LAT;

	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_SEQ][K2_REQ_512] =
		K2_SW_512_LAT;
	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_SEQ][K2_REQ_4096] =
		K2_SW_4096_LAT;
	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_SEQ][K2_REQ_508K] =
		K2_SW_508K_LAT;
	k2d->expected_latencies[K2_REQ_WRITE][K2_REQ_SEQ][K2_REQ_2M] =
		K2_SW_2M_LAT;

	k2d->load_mult[K2_REQ_READ] = K2_LOAD_ADJUST_DEFAULT;
	k2d->load_mult[K2_REQ_WRITE] = K2_LOAD_ADJUST_DEFAULT;

	rb = &k2d->last_read_ratios;
	ringbuf_init(rb, K2_LOAD_ADJUST_WINDOW_LEN, load_adjust_t);
	ringbuf_set_all(rb, K2_LOAD_ADJUST_MULT, load_adjust_t, ringbuf_iter);
	rb = &k2d->last_write_ratios;
	ringbuf_init(rb, K2_LOAD_ADJUST_WINDOW_LEN, load_adjust_t);
	ringbuf_set_all(rb, K2_LOAD_ADJUST_MULT, load_adjust_t, ringbuf_iter);

	INIT_LIST_HEAD(&k2d->global_k2_list_element);

	spin_lock_init(&k2d->lock);

	rq->elevator = eq;

	k2d->rq = rq;

	INIT_LIST_HEAD(&k2d->rt_dynamic_rqs);

	k2d->next_dynamic_deadline = S64_MAX;
	k2d->next_dynamic_deadline_pid = -1;

	// Register this instance so it can be addressed from ioctl
	if (k2_global_k2_dev) {
		list_add_tail(&k2d->global_k2_list_element,
			      &k2_global_k2_dev->k2_instances);
	} else {
		printk(KERN_WARNING
		       "Could not register k2 scheduler instance for device /dev/%s for ioctl interaction\n",
		       k2d->rq->disk->disk_name);
	}

	printk(KERN_INFO "k2: I/O scheduler set up for %s\n",
	       rq->disk->disk_name);
	return (0);
}

static void k2_exit_sched(struct elevator_queue *eq)
{
	struct k2_data *k2d = eq->elevator_data;
	char *blk_name = k2d->rq->disk->disk_name;
	struct ringbuf *rb;

	// Delete from global dev node
	if (k2_global_k2_dev) {
		list_del(&k2d->global_k2_list_element);
	}

	k2_del_all_dynamic_rt_rq(k2d);

	rb = &k2d->last_read_ratios;
	ringbuf_free(rb);
	rb = &k2d->last_write_ratios;
	ringbuf_free(rb);

	kfree(k2d);
	k2d = NULL;
	printk(KERN_INFO "k2: I/O scheduler unloaded for %s\n", blk_name);
}

static bool k2_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	bool has_work;
	unsigned long flags;

	spin_lock_irqsave(&k2d->lock, flags);
	has_work = _k2_has_work(k2d);
	spin_unlock_irqrestore(&k2d->lock, flags);

	return (has_work);
}

void k2_prepare_request(struct request *rq);

/* Inserts a request into the scheduler queue. For now, at_head is ignored! */
static void k2_insert_requests(struct blk_mq_hw_ctx *hctx,
			       struct list_head *rqs, bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	unsigned long flags;
	K2_LOG(printk("k2: TRY Entering insert on pid %d\n", current->pid);)

	spin_lock_irqsave(&k2d->lock, flags);

	while (!list_empty(rqs)) {
		struct request *rq;
		int prio_class;
		int prio_value;
		pid_t pid;
		struct list_head *list_item;
		struct list_head *k2_queue;
		struct k2_dynamic_rt_rq *rt_rqs;
		ktime_t now;

		K2_LOG(printk("k2: Entering insert on pid %d\n", current->pid);)

		rq = list_first_entry(rqs, struct request, queuelist);
		list_del_init(&rq->queuelist);

		k2_prepare_request(rq);

		K2_LOG(printk(KERN_WARNING
			      "k2: Insert %s REQ: size: %u (%u K), offset %llu, segments: %u  || BIO: how many bio bio_vecs %u \n",
			      k2_req_type_names[k2_req_type(rq)],
			      blk_rq_bytes(rq), blk_rq_bytes(rq) >> 10,
			      blk_rq_pos(rq), blk_rq_nr_phys_segments(rq),
			      rq->bio->bi_vcnt);)

		/* if task has no io prio, derive it from its nice value */
		if (ioprio_valid(rq->ioprio)) {
			prio_class = IOPRIO_PRIO_CLASS(rq->ioprio);
			prio_value = IOPRIO_PRIO_VALUE(prio_class, rq->ioprio);

		} else {
			k2_ioprio_from_task(&prio_class, &prio_value);
		}

		if (prio_value >= IOPRIO_BE_NR || prio_value < 0) {
			prio_value = IOPRIO_NORM;
		}

		// Add request to the rb tree of request for merge-checking
		k2_add_rq_rb(k2d, rq);
		// Add to generic elevator hash table for request merging
		// Why do both? -
		//  * internal scheduler hash table supports back merges
		//  * the elevator internal rb tree supports front merges
		if (rq_mergeable(rq)) {
			elv_rqhash_add(q, rq);
			if (!q->last_merge)
				q->last_merge = rq;
		}

		pid = current->pid;
		now = k2_now();

		K2_LOG(printk(KERN_INFO
			      "Insert: PID: %d, class: %d, level: %d, size: %u \n",
			      pid, prio_class, prio_value,
			      k2_get_rq_bytes(rq) / 1024);)

		// If there exists a dynamic realtime queue for this task, add the request there
		if (!list_empty(&k2d->rt_dynamic_rqs)) {
			list_for_each (list_item, &k2d->rt_dynamic_rqs) {
				rt_rqs = list_entry(list_item,
						    struct k2_dynamic_rt_rq,
						    list);
				if (rt_rqs->pid == pid) {
					K2_LOG(printk(
						KERN_INFO
						"k2: Insert request %pK to dynamic queue for pid %d and size %u\n",
						rq, pid, blk_rq_bytes(rq)));
					// Update the priority class of the dynamic queue
					rt_rqs->prio_class = prio_class;
					rt_rqs->prio_lvl = prio_value;

					//printk("k2: %llu %llu, %llu\n", rt_rqs->next_deadline, k2_now(), rt_rqs->next_deadline - k2_now());
					if (rt_rqs->next_deadline < now) {
						rt_rqs->next_deadline = ktime_add(
							now, rt_rqs->interval);
						if (rt_rqs->next_deadline <
							    k2d->next_dynamic_deadline ||
						    k2d->next_dynamic_deadline_pid ==
							    rt_rqs->pid) {
							k2d->next_dynamic_deadline =
								rt_rqs->next_deadline;
							k2d->next_dynamic_deadline_pid =
								rt_rqs->pid;
						}
					}

					// Enable the next statement to disable any merging attempts for dynamic rt requests
					//rq->cmd_flags |= REQ_NOMERGE;

					K2_LOG(printk(
						KERN_INFO
						"k2: set rt queue deadline for pid %d to %lld\n",
						pid, rt_rqs->next_deadline));
					K2_LOG(printk(KERN_WARNING
						      "k2: Insert dyn rt REQ: size: %u (%u K), offset %llu  || BIO: how many bio bio_vecs %u \n",
						      blk_rq_bytes(rq),
						      blk_rq_bytes(rq) >> 10,
						      blk_rq_pos(rq),
						      rq->bio->bi_vcnt);)

					k2_queue = &rt_rqs->reqs;
					goto insert_request;
				}
			}
		}

		// Else add it to regular queues
		if (prio_class == IOPRIO_CLASS_RT) {
			K2_LOG(printk(
				KERN_INFO
				"k2: Insert request %pK to static rt queue %d for pid %d\n",
				rq, prio_value, pid));
			k2_queue = &k2d->rt_reqs[prio_value];
		} else {
			K2_LOG(printk(
				KERN_INFO
				"k2: Insert request %pK to static be queue for pid %d\n",
				rq, pid));
			k2_queue = &k2d->be_reqs;
		}

	insert_request:
		// As of the documentation, this should be called "immediately before block operation request @rq is inserted
		// into queue @q"
		trace_block_rq_insert(rq);
		if (at_head) {
			list_add(&rq->queuelist, k2_queue);
		} else {
			list_add_tail(&rq->queuelist, k2_queue);
		}
	}
	spin_unlock_irqrestore(&k2d->lock, flags);
}

/**
 * @brief Helper macro that marks a request for dispatching
 * @details Avoid forgetting setting the last dispatch time
 */
#define k2_mark_for_dispatch(__request__, __last_dispatch_time__)              \
	dispatched_rq = (__request__);                                         \
	last_dispatch_dispatched = (__last_dispatch_time__);

static struct request *k2_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	struct request *regular_rq = NULL;
	struct request *dynamic_rq = NULL;
	ktime_t *last_regular_dispatch = NULL;
	ktime_t *last_dynamic_dispatch = NULL;
	struct request *dispatched_rq = NULL;
	ktime_t *last_dispatch_dispatched = NULL;

	struct list_head *list_elem;
	struct k2_dynamic_rt_rq *rt_rqs;

	u8 highest_regular_rq_class =
		IOPRIO_CLASS_IDLE + 1; // Lowest possible priority class + 1
	u8 highest_regular_rq_lvl =
		IOPRIO_NR_LEVELS + 1; // Lowest possible priority level + 1
	u8 highest_dynamic_rq_class =
		IOPRIO_CLASS_IDLE + 1; // Lowest possible priority class + 1
	u8 highest_dynamic_rq_lvl =
		IOPRIO_NR_LEVELS + 1; // Lowest possible priority level + 1

	struct k2_dynamic_rt_rq *next_rt_rqs = NULL;
	struct k2_dynamic_rt_rq *dispatched_rt_rqs = NULL;
	bool *consider_regular_rq;

	ktime_t now;

	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&k2d->lock, flags);

	/* Situation might have change since the last call to has_work() */
	if (!_k2_has_work(k2d)) {
		K2_LOG(printk(KERN_INFO "k2: no run dispatch!\n");)
		goto abort;
	}

	now = k2_now();

	// Check all queues for starvation
	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each (list_elem, &k2d->rt_dynamic_rqs) {
			rt_rqs = list_entry(list_elem, struct k2_dynamic_rt_rq,
					    list);
			if (!list_empty(&rt_rqs->reqs)) {
				if (now - rt_rqs->last_dispatch >
				    K2_MAX_QUEUE_WAIT) {
					k2_mark_for_dispatch(
						list_first_entry(&rt_rqs->reqs,
								 struct request,
								 queuelist),
						&rt_rqs->last_dispatch);
					dispatched_rt_rqs = rt_rqs;
					printk(KERN_INFO
					       "k2: Dispatch to prevent starvation dyn\n");
					goto end;
				}
			}
		}
	}

	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (!list_empty(&k2d->rt_reqs[i])) {
			if (now - k2d->last_rt_queue_dispatches[i] >
			    K2_MAX_QUEUE_WAIT) {
				k2_mark_for_dispatch(
					list_first_entry(&k2d->rt_reqs[i],
							 struct request,
							 queuelist),
					&k2d->last_rt_queue_dispatches[i]);
				printk(KERN_INFO
				       "k2: Dispatch to prevent starvation rt\n");
				goto end;
			}
		}
	}

	if (!list_empty(&k2d->be_reqs)) {
		if (now - k2d->last_be_queue_dispatch > K2_MAX_QUEUE_WAIT) {
			k2_mark_for_dispatch(list_first_entry(&k2d->be_reqs,
							      struct request,
							      queuelist),
					     &k2d->last_be_queue_dispatch);
			printk(KERN_INFO
			       "k2: Dispatch to prevent starvation be\n");
			goto end;
		}
	}

	// Check regular queues

	// Realtime requests
	// As the order of static rt queues is descending in priority level,
	// the search can be aborted after a hit
	for (i = 0; i < IOPRIO_NR_LEVELS; i++) {
		if (!list_empty(&k2d->rt_reqs[i])) {
			regular_rq = list_first_entry(
				&k2d->rt_reqs[i], struct request, queuelist);
			last_regular_dispatch =
				&k2d->last_rt_queue_dispatches[i];
			highest_regular_rq_class = IOPRIO_CLASS_RT;
			highest_regular_rq_lvl = i;
			consider_regular_rq =
				&k2d->scheduled_regular_rt_queue_last[i];
			goto check_registered;
		}
	}

	// Best effort requests
	if (!list_empty(&k2d->be_reqs)) {
		regular_rq = list_first_entry(&k2d->be_reqs, struct request,
					      queuelist);
		last_regular_dispatch = &k2d->last_be_queue_dispatch;
		highest_regular_rq_class = IOPRIO_CLASS_BE;
		consider_regular_rq = &k2d->scheduled_regular_be_queue_last;
	}

check_registered:
	/*
    * Check registered tasks
    *
    * Fairness between registered queues of the same priority:
    * The registered queues are organized in a list structure inside the k2_data.
    * This list is iterated from front to back on each dispatch
    * If we encounter a queue with the same or higher priority, favor this one over any previously found queues
    * If this queue is selected for dispatch, we move the list entry to the front of the list
    * --> The next time, another queue of the same priority will be selected for dispatch
    */
	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each (list_elem, &k2d->rt_dynamic_rqs) {
			rt_rqs = list_entry(list_elem, struct k2_dynamic_rt_rq,
					    list);

			// Get the next deadline of any rt queues
			if (NULL != next_rt_rqs) {
				if (next_rt_rqs->next_deadline <
				    rt_rqs->next_deadline) {
					next_rt_rqs = rt_rqs;
				}
			} else {
				next_rt_rqs = rt_rqs;
			}

			if (!list_empty(&rt_rqs->reqs)) {
				// If the request's deadline is reached, schedule it no matter what
				if (rt_rqs->next_deadline <= now) {
					printk(KERN_INFO
					       "k2: Realtime Deadline %d: %llu, %lld, %lld\n",
					       rt_rqs->pid,
					       rt_rqs->next_deadline, now,
					       rt_rqs->next_deadline - now);
					last_dynamic_dispatch =
						&rt_rqs->last_dispatch;
					k2_mark_for_dispatch(
						list_first_entry(&rt_rqs->reqs,
								 struct request,
								 queuelist),
						last_dynamic_dispatch);
					dispatched_rt_rqs = rt_rqs;
					goto dynamic_end;
				}

				// Get the registered request with the highest priority
				if (rt_rqs->prio_class <=
				    highest_dynamic_rq_class) {
					if (rt_rqs->prio_lvl <=
					    highest_dynamic_rq_lvl) {
						dynamic_rq = list_first_entry(
							&rt_rqs->reqs,
							struct request,
							queuelist);
						last_dynamic_dispatch =
							&rt_rqs->last_dispatch;
						highest_dynamic_rq_class =
							rt_rqs->prio_class;
						highest_dynamic_rq_lvl =
							rt_rqs->prio_lvl;
						dispatched_rt_rqs = rt_rqs;
					}
				}
			} else {
			}
		}
	}

	if (NULL == regular_rq && NULL == dynamic_rq) {
		goto abort;
	}

	if (highest_regular_rq_class < highest_dynamic_rq_class) {
		//printk("k2: dispatch regular 1\n");
		k2_mark_for_dispatch(regular_rq, last_regular_dispatch);
		dispatched_rt_rqs = NULL;
	} else if (highest_regular_rq_class > highest_dynamic_rq_class) {
		//printk("k2: dispatch dynamic 1\n");
		k2_mark_for_dispatch(dynamic_rq, last_dynamic_dispatch);
	} else {
		if (highest_regular_rq_lvl < highest_dynamic_rq_lvl) {
			//printk("k2: dispatch regular 2\n");
			k2_mark_for_dispatch(regular_rq, last_regular_dispatch);
			dispatched_rt_rqs = NULL;
		} else if (highest_regular_rq_lvl > highest_dynamic_rq_lvl) {
			//printk("k2: dispatch dynamic 2\n");
			k2_mark_for_dispatch(dynamic_rq, last_dynamic_dispatch);
		} else {
			// Both the regular queues and the dynamic queues have the same prio value,
			// Round-robin requests queues of the same priority between static and dynamic queues
			if (*consider_regular_rq) {
				//printk("k2: dispatch regular 3\n");
				k2_mark_for_dispatch(regular_rq,
						     last_regular_dispatch);
				dispatched_rt_rqs = NULL;
			} else {
				//printk("k2: dispatch dynamic 3\n");
				k2_mark_for_dispatch(dynamic_rq,
						     last_dynamic_dispatch);
			}
			//printk(KERN_ERR "k2: consider regular: %d\n", *consider_regular_rq);
			*consider_regular_rq = !*consider_regular_rq;
		}
	}

end:
	// A request from a non registered realtime task has to be checked to interfere with performance goals
	// If it does not fit, no request is dispatched
	K2_LOG(printk(KERN_INFO "k2: Try Dispatch request %pK\n",
		      dispatched_rq));
	k2_set_rq_latency(dispatched_rq,
			  k2_expected_request_latency(k2d, dispatched_rq));
	if (!k2_does_request_fit_check_registered_queues(k2d, dispatched_rq,
							 next_rt_rqs)) {
		K2_LOG(u16 val = k2_get_rq_schedule_attempts_rt_constraint(
			       dispatched_rq);
		       if (val > max_retries) {
			       max_retries = val;
			       printk(KERN_INFO
				      "k2: Dispatch request %pK ABORTED, %u, %u, %u, %px\n",
				      dispatched_rq, val, max_retries,
				      k2_get_rq_pid(dispatched_rq),
				      dispatched_rq->elv.priv[1]);
		       })
		goto abort;
	}
	goto dispatch;

dynamic_end:
	// Realtime tasks in their deadline get scheduled either way
	k2_set_rq_latency(dispatched_rq,
			  k2_expected_request_latency(k2d, dispatched_rq));

dispatch:
	K2_LOG(printk(KERN_INFO "k2: Dispatch request %pK, %d\n", dispatched_rq,
		      k2_get_rq_pid(dispatched_rq));)
	k2_remove_request(q, dispatched_rq);
	k2_add_latency(k2d, dispatched_rq);
	dispatched_rq->rq_flags |= RQF_STARTED;
	*last_dispatch_dispatched = now;

	if (NULL != dispatched_rt_rqs) {
		list_move(&dispatched_rt_rqs->list, &k2d->rt_dynamic_rqs);
		dispatched_rt_rqs->next_deadline =
			ktime_add(k2_now(), dispatched_rt_rqs->interval);
		if (dispatched_rt_rqs->next_deadline <
			    k2d->next_dynamic_deadline ||
		    k2d->next_dynamic_deadline_pid == dispatched_rt_rqs->pid) {
			k2d->next_dynamic_deadline =
				dispatched_rt_rqs->next_deadline;
			k2d->next_dynamic_deadline_pid = dispatched_rt_rqs->pid;
		}
	}

	spin_unlock_irqrestore(&k2d->lock, flags);

	return (dispatched_rq);

abort:
	spin_unlock_irqrestore(&k2d->lock, flags);
	K2_LOG(printk("k2: Dispatch aborted\n");)

	return (NULL);
}

/**
 * @brief Decide, weather a new bio is allowed to merged to one of the existing requests
 * @detals Called from within blk_bio_list_merge(), if no merge_bio() callback is registered; and blk_mq_sched_try_merge()
 * @param q The software queue this bio belongs to
 * @param rq The request to merge the bio with
 * @param bio The bio to merge
 * @return If the bio is allowed to be merged generically by the block layer
 */
bool k2_allow_merge(struct request_queue *q, struct request *rq,
		    struct bio *bio)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	int ret = true;
	struct list_head *list_elem;
	struct k2_dynamic_rt_rq *rt_rqs;
	pid_t pid_cur = current->pid;
	pid_t pid_req = k2_get_rq_pid(rq);

	// If the request comes from the same process, allow merging
	if (pid_cur == pid_req) {
		K2_LOG(printk(KERN_INFO "k2: allow merge same pid\n"));
		ret = true;
		goto ret;
	}

	// This lock should be set by the invoking k2_bio_merge
	assert_spin_locked(&k2d->lock);
	// Do not allow for registered realtime requests to get merged with a request from any other task
	if (!list_empty(&k2d->rt_dynamic_rqs)) {
		list_for_each (list_elem, &k2d->rt_dynamic_rqs) {
			rt_rqs = list_entry(list_elem, struct k2_dynamic_rt_rq,
					    list);
			if (pid_cur == rt_rqs->pid || pid_req == rt_rqs->pid) {
				K2_LOG(printk(
					KERN_INFO
					"k2: allow merge NO, rt involved \n"));
				ret = false;
				goto finally;
			}
		}
	}
	K2_LOG(printk(KERN_INFO "k2: allow merge , no problem\n"));

finally:
ret:
	K2_LOG(printk(KERN_INFO
		      "k2: k2_allow_merge: %d , req: %d, with new bio pid %d\n",
		      ret, pid_req, pid_cur));

	return ret;
}

/**
 * @brief Check for a bio, if it can be merged with any outstanding requests in the elevator queues
 * @details Called from within submit_bio(), whenever a new bio arrives (some constraints apply before)
 * @param q The software queue this bio belongs to
 * @param bio The new bio
 * @param nr_segments The count of bio segments
 * @return True, if there was a merge, else false
 */
static bool k2_bio_merge(struct request_queue *q, struct bio *bio,
			 unsigned int nr_segments)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *free = NULL;
	unsigned long flags;
	bool ret;

	K2_LOG(printk(KERN_INFO "k2: Entering k2_bio_merge\n"));

	spin_lock_irqsave(&k2d->lock, flags);
	ret = blk_mq_sched_try_merge(q, bio, &free);
	spin_unlock_irqrestore(&k2d->lock, flags);

	K2_LOG(if (ret) printk(KERN_INFO
			       "k2: k2_bio_merge: Performed a merge\n");)

	if (free)
		blk_mq_free_request(free);

	return (ret);
}

/**
 * @brief Try to find a merge candidate for a new bio with a request in the current software queues
 * @details Called from within blk_mq_sched_try_merge() (this is called from k2_bio_merge()).
 *  If the merge was successful, k2_request_merged() is called.
 *  This custom implementation by Weisbach uses a rb tree to store every request in the
 *  software queues for front merge checking.
 * @param q The software queue this bio belongs to
 * @param rq Return parameter: The request this bio was merged with, else NULL
 * @param bio The new bio
 * @return The status code of the operation (enum elv_merge)
 */
static int k2_request_merge(struct request_queue *q, struct request **rq,
			    struct bio *bio)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *__rq;
	sector_t sector = bio_end_sector(bio);

	K2_LOG(printk(KERN_INFO "k2: Entering k2_request_merge\n"));

	// should request merging cross I/O prios?

	__rq = elv_rb_find(&k2d->sort_list[bio_data_dir(bio)], sector);
	if (__rq) {
		BUG_ON(sector != blk_rq_pos(__rq));

		// Checks k2_allow_merge
		if (elv_bio_merge_ok(__rq, bio)) {
			*rq = __rq;
			K2_LOG(printk(KERN_INFO
				      "k2 Did a request front merge\n"));
			return (ELEVATOR_FRONT_MERGE);
		}
	}

	return (ELEVATOR_NO_MERGE);
}

/**
 * @brief Invoked after a bio was successfully merged into a existing request
 * @param q The software queue of the request
 * @param rq The request that was merged
 * @param type The type of the merge
 */
static void k2_request_merged(struct request_queue *q, struct request *rq,
			      enum elv_merge type)
{
	struct k2_data *k2d = q->elevator->elevator_data;

	K2_LOG(printk(KERN_INFO "k2: Entering k2_request_merged\n"));

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	if (type == ELEVATOR_FRONT_MERGE) {
		k2_del_rq_rb(k2d, rq);
		k2_add_rq_rb(k2d, rq);
	}
}

/**
 * @brief Invoked whenever a request was merged with another request
 * @details
 * @param q The software queue of the existing request
 * @param rq The request that the other request was merged with
 * @param next The new request that was merged. This object is no longer valid.
 */
static void k2_requests_merged(struct request_queue *q, struct request *rq,
			       struct request *next)
{
	struct k2_data *k2d = rq->q->elevator->elevator_data;
	unsigned long flags;

	K2_LOG(printk(KERN_INFO "k2: Entering k2_requests_merged\n"));
	if (!k2_rq_is_managed_by_k2(rq) || !k2_rq_is_managed_by_k2(next)) {
		printk(KERN_ERR
		       "k2: Merged 2 requests, where at least one was not managed by k2 before!\n");
		dump_stack();
	}

	spin_lock_irqsave(&k2d->lock, flags);

	k2_remove_request(q, next);
	k2_set_rq_attempts_rt_constrain(
		rq, max(k2_get_rq_schedule_attempts_rt_constraint(rq),
			k2_get_rq_schedule_attempts_rt_constraint(next)));

	spin_unlock_irqrestore(&k2d->lock, flags);
}

static void k2_completed_request(struct request *rq, u64 now)
{
	struct k2_data *k2d = rq->q->elevator->elevator_data;
	unsigned long flags;
	latency_ns_t current_lat;
	latency_ns_t max_lat;
	latency_ns_t real_latency;
	struct list_head *list_elem;
	struct k2_dynamic_rt_rq *rt_rqs;
	unsigned inflight;
	struct ringbuf *rb;
	bool has_work;

	spin_lock_irqsave(&k2d->lock, flags);

	real_latency = (now >= rq->io_start_time_ns) ?
			       now - (latency_ns_t)rq->io_start_time_ns :
				     0;

	current_lat = k2d->current_inflight_latency;
	max_lat = k2d->max_inflight_latency;
	inflight = k2d->inflight;

	// This request has been touched by the scheduler before.
	// If this is not the case, it is most likely a flush request, which uses the elv.priv fields for flush data.
	// Both structs are contained in the same union.
	if (k2_rq_is_managed_by_k2(rq)) {
		K2_LOG(printk(KERN_INFO
			      "k2: Completed %s request %px for process with PID %d and request size %u, sectors %d, Real latency: %lld, estimated latency: %lld\n",
			      k2_req_type_names[k2_req_type(rq)], rq,
			      k2_get_rq_pid(rq),
			      (blk_rq_stats_sectors(rq) << SECTOR_SHIFT) >> 10,
			      blk_rq_stats_sectors(rq), real_latency,
			      k2_get_rq_latency(rq));)
		k2_remove_latency(k2d, rq);
		trace_k2_completed_request(rq, real_latency);

		// If the request was delivered by a dynamic realtime queue, update their processing time
		if (!list_empty(&k2d->rt_dynamic_rqs)) {
			list_for_each (list_elem, &k2d->rt_dynamic_rqs) {
				rt_rqs = list_entry(list_elem,
						    struct k2_dynamic_rt_rq,
						    list);
				if (rt_rqs->pid == k2_get_rq_pid(rq)) {
					rt_rqs->last_request_latency =
						real_latency;
					break;
				}
			}
		}

#if K2_ENABLE_LOAD_ADJUST == 1
		// Adjust dynamic load multiplier
		switch (k2_req_type(rq)) {
		case K2_REQ_READ:
			rb = &k2d->last_read_ratios;
			k2_load_adjust_sliding_window(
				&k2d->load_mult[K2_REQ_READ], rb,
				k2_get_rq_latency(rq), real_latency);
			break;
		case K2_REQ_WRITE:
			rb = &k2d->last_write_ratios;
			k2_load_adjust_sliding_window(
				&k2d->load_mult[K2_REQ_WRITE], rb,
				k2_get_rq_latency(rq), real_latency);
			break;
		default:
			break;
		}
#endif
#if K2_ENABLE_ACCESS_PATTERN == 1
		k2d->last_dispatched_sector = blk_rq_pos(rq);
#endif
	}

	has_work = _k2_has_work(k2d);

	spin_unlock_irqrestore(&k2d->lock, flags);

	/*
    * This completion call creates leeway for dispatching new requests.
    * Rerunning the hw queues have to be done manually since we throttle
    * request dispatching. Mind that this has to be executed in async mode.
    */
	K2_LOG(printk(KERN_INFO "Current lat: %llu, max lat: %llu\n",
		      current_lat, max_lat));
	if (has_work) {
		K2_LOG(printk(KERN_INFO "k2: Rerun hardware queues\n"));
		blk_mq_run_hw_queues(rq->q, true);
	} else {
		K2_LOG(printk(KERN_INFO "k2: Do not rerun hardware queues\n");)
	}
}

void k2_prepare_request(struct request *rq)
{
	pid_t pid = current->pid;

	rq->elv.priv[0] = NULL;
	rq->elv.priv[1] = NULL;

	// For some unknown reason, this flag is set in the block layer only
	// if the prepare_request() callback is invoked, and even then, after the callback's invocation
	// This flag is required in k2_complete_request() To only process valid requests, that previously passed k2
	// However, When using this function as a callback for elv.ops.prepare_request(), the request size is not yet available,
	// thus, it is invoked manually in k2_insert_request() and the RQF_ELVPRIV is set manually.
	rq->rq_flags |= RQF_ELVPRIV;

	k2_set_rq_pid(rq, pid);
}

/**
 * @brief Declare required structs
 * @details For some unknown reason, the structs in the parameter list of elevator functions are not defined in the installed kernel headers,
 * they are only included in the kernel source tree. 150 IQ moves over here...
 * We copy the struct definition in order to use the functions offered in the exported headers.
 *
 * On some point later in time, these structs might change upstream and things will get ugly.
 * TODO: Watch out!
 */
struct blk_mq_alloc_data {
	/* input parameter */
	struct request_queue *q;
	blk_mq_req_flags_t flags;
	unsigned int shallow_depth;
	unsigned int cmd_flags;

	/* input & output parameter */
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};

struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;

	atomic_t active_queues;

	struct sbitmap_queue *bitmap_tags;
	struct sbitmap_queue *breserved_tags;

	struct sbitmap_queue __bitmap_tags;
	struct sbitmap_queue __breserved_tags;

	struct request **rqs;
	struct request **static_rqs;
	struct list_head page_list;

	/*
     * used to clear request reference in rqs[] before freeing one
     * request pool
     */
	spinlock_t lock;
};

static void k2_depth_updated(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = q->elevator->elevator_data;
	struct blk_mq_tags *tags = hctx->sched_tags;
	unsigned int shift = tags->bitmap_tags->sb.shift;

	k2d->async_depth = (1U << shift) * K2_ASYNC_PERCENTAGE / 100U;
	K2_LOG(printk(KERN_INFO "k2: Set async depth to %u\n",
		      k2d->async_depth);)

	sbitmap_queue_min_shallow_depth(tags->bitmap_tags, k2d->async_depth);
}

/**
 * @brief Set initial async request limit
 */
static int k2d_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	k2_depth_updated(hctx);
	return 0;
}

/**
 * @brief Limit the software queue length for async requests.
 * @details Synchronous requests will be stalled by the sheer amount of asynchronous request pressure and will fail their performance goals,
 * simply because the do not get to insert their request to the scheduler.
 * @param op OpCode of the request
 */
static void k2_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	if (!op_is_sync(op)) {
		struct k2_data *k2d = data->q->elevator->elevator_data;
		K2_LOG(printk(KERN_INFO "k2: GET async depth of %u\n",
			      k2d->async_depth);)

		data->shallow_depth = k2d->async_depth;
	}
}

static struct elevator_type k2_iosched = {
	.ops = {
		.init_sched        = k2_init_sched,
		.exit_sched        = k2_exit_sched,

		.insert_requests   = k2_insert_requests,
		.has_work          = k2_has_work,
		.dispatch_request  = k2_dispatch_request,
		.completed_request = k2_completed_request,

		.allow_merge       = k2_allow_merge,
		.bio_merge         = k2_bio_merge,
		.request_merge     = k2_request_merge,
		.request_merged    = k2_request_merged,
		.next_request      = elv_rb_latter_request,
		.former_request	   = elv_rb_former_request,
		.requests_merged   = k2_requests_merged,

		.limit_depth       = k2_limit_depth,
		.depth_updated     = k2_depth_updated,
		.init_hctx         = k2d_init_hctx,
	},
	.elevator_attrs = k2_attrs,
	.elevator_name  = "k2",
	.elevator_owner = THIS_MODULE,
};

/* =============================
 * ==== MODULE REGISTRATION ====
 * ========================== */

static int __init k2_init(void)
{
	int error = 0;
	printk(KERN_INFO "k2: Loading K2 I/O scheduler.\n");
	error = k2_init_dev();
	if (error) {
		return error;
	}
	return elv_register(&k2_iosched);
}

static void __exit k2_exit(void)
{
	printk(KERN_INFO "k2: Unloading K2 I/O scheduler.\n");
	elv_unregister(&k2_iosched);
	k2_close_dev(k2_global_k2_dev);
}

module_init(k2_init);
module_exit(k2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Till Miemietz, Georg Grassnick");
MODULE_DESCRIPTION("A work-constraining I/O scheduler with real-time notion.");
MODULE_VERSION("0.2");
