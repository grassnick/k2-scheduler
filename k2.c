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


/*
 * TODO:
 * * sysfs interface for setting queue length in us rather than inflight count
 * * calculate request time for each access in insert_requests
 *      * Static table for expected / benchmarked request types
 *      * Offer adjustments for expected access time for
 *          * reads (use random read values by default)
 *          * writes (use random write values by default)
 * * attach expected request time request object / if not possible, add global struct which somehow? manages access times
 * * Do not block if there are currently no inflight requests -> avoid stalling queue if all remaining elements are expected to exceed queue limit
 *
 * in dispatch, check if current timing requirements can be matched
 *      * check if expected request time is longer than what's over in the in flight time
 * *
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

#define CREATE_TRACE_POINTS

// Tracing related
#include "k2_trace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(k2_completed_request);

// Device and ioctl related
#include "k2.h"

/** Macro to disable Kernel massages meant for debugging */
#define K2_LOG(log)

/** A type that represents the latency of a request in us */
typedef u32 latency_us_t;
#define LATENCY_US_T_MAX U32_MAX

/** The initial value for the maximum in-flight latency */
#define K2_MAX_INFLIGHT_USECONDS 62490 * 4

#define K2_RR_512_LAT   61570
#define K2_RR_32K_LAT   70905
#define K2_RR_2048K_LAT 686210

#define K2_RW_512_LAT   68285
#define K2_RW_32K_LAT   76260
#define K2_RW_2048K_LAT 707430

#define K2_512 512
#define K2_32K 32 << 10
#define K2_2048K 2 << 20

extern bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
		struct request **merged_request);

/* ===============================
 * ===== STRUCT DEFINITIONS ======
 * ============================ */

/**
 * @brief Global K2 data structure
 * @details This struct is initialized by the scheduler itself exactly once.
 *  Parallel modifications to this struct MUST ensure synchronous access provided via the k2_data::lock member
 */
struct k2_data {
	unsigned int inflight;
    latency_us_t current_inflight_latency;
    latency_us_t max_inflight_latency;
    latency_us_t lowest_upcoming_latency;

    /* Expected latencies for typical access sizes */
    /* Random Read */
    latency_us_t rr_512_lat;
    latency_us_t rr_32K_lat;
    latency_us_t rr_2048K_lat;

    /* Random Write */
    latency_us_t rw_512_lat;
    latency_us_t rw_32K_lat;
    latency_us_t rw_2048K_lat;

	/* further group real-time requests by I/O priority */
	struct list_head rt_reqs[IOPRIO_BE_NR];
	struct list_head be_reqs;

	/* Sector-ordered lists for request merging */
	struct rb_root sort_list[2];

	spinlock_t lock;

    /* Collect k2_data structs for different gendisks in the global struct */
    struct list_head global_k2_list_element;

    /* The request queue this elevator is attached to */
    struct request_queue* rq;

    /* Dynamically generated realtime I/O request queues */
    struct list_head rt_dynamic_rqs;
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
     * @brief IO Priority class of the process - this can change dynamically!
     * @details read directly from head request
     */
    //u8 prio;

    /**
     * @brief The interval, these requests will occur
     */
     latency_us_t interval;

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

static int k2_add_dynamic_rt_rq(struct k2_data* k2d, pid_t pid, latency_us_t interval);
static int k2_del_dynamic_rt_rq(struct k2_data* k2d, pid_t pid);
static struct k2_data* k2_get_k2d_by_disk(const char* disk_name);

/* =========================
 * ===== SYSFS RELATED =====
 * ====================== */

ssize_t k2_max_inflight_latency_show(struct elevator_queue *eq, char *s)
{
    struct k2_data *k2d = eq->elevator_data;

    return(sprintf(s, "%u\n", k2d->max_inflight_latency));
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
        printk(KERN_INFO "k2: max_inflight set to %u\n",
               k2d->max_inflight_latency);

        return(size);
    }

    /* error, leave max_inflight as is */
    return(size);
}

ssize_t current_inflight_latency_show(struct elevator_queue *eq, char *s)
{
    struct k2_data *k2d = eq->elevator_data;
    return(sprintf(s, "%u\n", k2d->current_inflight_latency));
}

ssize_t current_inflight_show(struct elevator_queue *eq, char *s)
{
    struct k2_data *k2d = eq->elevator_data;
    return(sprintf(s, "%u\n", k2d->inflight));
}

static struct elv_fs_entry k2_attrs[] = {
    __ATTR_RO(current_inflight),
    __ATTR(max_inflight_latency, S_IRUGO | S_IWUSR, k2_max_inflight_latency_show,k2_max_inflight_latency_set),
    __ATTR_RO(current_inflight_latency),
    __ATTR_NULL};


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
     * @brief device not handle for registration on /dev
     */
    struct device *device;

    /**
     * @brief list of running instances of the scheduler per gendisk
     */
    struct list_head k2_instances;

    spinlock_t lock;

    // TODO: Add lock to cover race conditions
};

/**
 * @brief Global device pointer for ioctl interaction
 * @details Always check for NULL, make sure to deallocate on module cleanup
 */
static struct k2_dev *k2_global_k2_dev = NULL;


static int k2_dev_open(struct inode *inode, struct file *filp) { return 0; }

static int k2_dev_release(struct inode *inode, struct file *filp) { return 0; }

/**
 * @brief Entry point for ioctl requests
 */
static long k2_dev_ioctl(struct file *file, unsigned int cmd,
                         unsigned long arg) {
    // struct inode *inode = file_inode(file);

    void __user *argp = (void __user *) arg;
    unsigned long ret = 0;
    struct k2_ioctl ioctl;
    char dev[K2_IOCTL_BLK_DEV_NAME_LENGTH];
    struct list_head* list_element;
    struct k2_data* k2d;
    char string_param[K2_IOCTL_CHAR_PARAM_LENGTH];
    char* separator = ";";

    memset(string_param, 0, K2_IOCTL_CHAR_PARAM_LENGTH);
    memset(dev, 0, K2_IOCTL_BLK_DEV_NAME_LENGTH);
    memset(&ioctl, 0, sizeof(ioctl));

    switch (cmd) {

        case K2_IOC_GET_VERSION:
            ret = copy_from_user(&ioctl, argp, sizeof(struct k2_ioctl));
            if (ret) {
                break;
            }
            ret = copy_to_user(ioctl.string_param, THIS_MODULE->version, min(strlen(THIS_MODULE->version), (unsigned long)K2_IOCTL_CHAR_PARAM_LENGTH));
            break;

        case K2_IOC_CURRENT_INFLIGHT_LATENCY:
            ret = copy_from_user(&ioctl, argp, sizeof(struct k2_ioctl));
            if (ret) {
                break;
            }
            ret = copy_from_user(dev, ioctl.blk_dev,
                                 K2_IOCTL_BLK_DEV_NAME_LENGTH);
            if (ret) {
                break;
            }
            ioctl.u32_param = K2_MAX_INFLIGHT_USECONDS;
            ret = copy_to_user(argp, &ioctl, sizeof(struct k2_ioctl));
            break;

        case K2_IOC_REGISTER_PERIODIC_TASK:
            ret = copy_from_user(&ioctl, argp, sizeof(ioctl));
            if(ret) {
              break;
            }
            ret = copy_from_user(dev, ioctl.blk_dev, K2_IOCTL_BLK_DEV_NAME_LENGTH);
            if(ret) {
              break;
            }
            printk(KERN_INFO "k2: Requesting periodic task with PID %u and interval of %u ns for %s\n"
                   , ioctl.task_pid, ioctl.interval_ns, dev);
            k2d = k2_get_k2d_by_disk(dev);
            if (NULL == k2d) {
                return -ENOENT;
            }
            ret = k2_add_dynamic_rt_rq(k2d, ioctl.task_pid, ioctl.interval_ns);
            if (ret) {
                break;
            }
            printk(KERN_INFO "k2: Registered periodic task with pid %d on %s", ioctl.task_pid, dev);
            break;

        case K2_IOC_UNREGISTER_PERIODIC_TASK:
            ret = copy_from_user(&ioctl, argp, sizeof(ioctl));
            if(ret) {
                break;
            }
            ret = copy_from_user(dev, ioctl.blk_dev, K2_IOCTL_BLK_DEV_NAME_LENGTH);
            if(ret) {
                break;
            }
            printk(KERN_INFO "k2: Requesting unregistration of periodic task with PID %u and interval of %u ns for %s\n"
            , ioctl.task_pid, ioctl.interval_ns, dev);

            k2d = k2_get_k2d_by_disk(dev);
            if (NULL == k2d) {
                return -ENOENT;
            }
            ret = k2_del_dynamic_rt_rq(k2d, ioctl.task_pid);
            if (ret) {
                break;
            }
            printk(KERN_INFO "k2: Unegistered periodic task with pid %d on %s", ioctl.task_pid, dev);
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
                k2d = list_entry(list_element, struct k2_data, global_k2_list_element);
                printk(KERN_INFO "k2: k2 is active on /dev/%s\n", k2d->rq->disk->disk_name);
                if (strlen(string_param) + strlen(k2d->rq->disk->disk_name) + strlen(separator) < K2_IOCTL_CHAR_PARAM_LENGTH) {
                    strcpy(string_param + strlen(string_param), separator);
                    memcpy(string_param + strlen(string_param), k2d->rq->disk->disk_name, strlen(k2d->rq->disk->disk_name));
                }
                if (list_element->next) {
                    list_element = list_element->next;
                }
            }
            printk(KERN_INFO "k2: k2 is active on %s\n", string_param);

            ret = copy_to_user(ioctl.string_param, string_param, K2_IOCTL_CHAR_PARAM_LENGTH);

            break;
        default:
            return -EINVAL;
    }
    return (long) ret;
}

static const struct file_operations k2_dev_fops = {
        .owner = THIS_MODULE,
        .llseek = noop_llseek,// As in btrfs driver registration
        .read = NULL,
        .write = NULL,
        .open = k2_dev_open,
        .release = k2_dev_release,
        .unlocked_ioctl = k2_dev_ioctl,
        .compat_ioctl = compat_ptr_ioctl,// https://docs.kernel.org/driver-api/ioctl.html#bit-compat-mode
};

static void k2_close_dev(struct k2_dev* device) {
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
    printk(KERN_INFO "k2: Unregistered device node: /dev/%s", K2_DEVICE_NAME);
}

static int k2_init_dev(void) {
    dev_t device_id;
    int error = 0;
    struct class *k2_class = NULL;
    struct device *k2_device = NULL;
    struct k2_dev* dev;

    dev = kzalloc(sizeof(struct k2_dev), GFP_KERNEL);
    if (NULL == dev) {
        printk(KERN_ERR
                       "k2: could not allocate device: device struct kzalloc() failed");
        return -ENOMEM;
    }

    error = alloc_chrdev_region(&device_id, 0, K2_NUMBER_DEVICES, K2_DEVICE_NAME);
    if (error < 0) {
        printk(KERN_ERR
               "k2: could not allocate device: alloc_chrdev_region() failed: %d",
               error);
        goto abort;
    }

    spin_lock_init(&dev->lock);

    cdev_init(&dev->cdev, &k2_dev_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &k2_dev_fops;
    error = cdev_add(&dev->cdev, device_id, 1);
    if (error) {
        printk(KERN_ERR "k2: could not allocate device: cdev_add() failed");
        goto abort;
    }

    printk(KERN_INFO "k2: Initialized device with Major device number: %d and "
                     "Minor device number: %d",
           MAJOR(dev->cdev.dev), MINOR(dev->cdev.dev));

    k2_class = class_create(THIS_MODULE, K2_DEVICE_NAME);
    if (IS_ERR(k2_class)) {
        printk(KERN_ERR "k2: could not allocate device: class_create() failed");
        error = -EEXIST;// I do not know what else to put here :/
        goto abort;
    }

    k2_device = device_create(k2_class, NULL, device_id, NULL, K2_DEVICE_NAME);
    if (IS_ERR(k2_device)) {
        printk(KERN_ERR "k2: could not allocate device: device_create() failed");
        class_destroy(k2_class);
        error = -EEXIST;// I do not know what else to put here :/
        goto abort;
    }

    INIT_LIST_HEAD(&dev->k2_instances);
    dev->device = k2_device;

    k2_global_k2_dev = dev;
    printk(KERN_INFO "k2: Initialized device node: /dev/%s", K2_DEVICE_NAME);

    return 0;

abort:
    k2_close_dev(dev);
    return error;
}

/* =============================
 * ==== K2 helper functions ====
 * ========================== */

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

static void k2_ioprio_from_task(int *class, int *value)
{
    if (current->io_context == NULL ||
        !ioprio_valid(current->io_context->ioprio)) {
        *class = task_nice_ioclass(current);
        *value = IOPRIO_NORM;
    } else {
        *class = IOPRIO_PRIO_CLASS(current->io_context->ioprio);
        *value = IOPRIO_PRIO_VALUE(*class, current->io_context->ioprio);
    }
}

static bool _k2_has_work(struct k2_data *k2d)
{
    unsigned int  i;

    assert_spin_locked(&k2d->lock);

    if (k2d->max_inflight_latency - k2d->current_inflight_latency < k2d->lowest_upcoming_latency && k2d->inflight > 0) {
        return(false);
    }

    if (! list_empty(&k2d->be_reqs)) {
        return (true);
    }

    for (i = 0; i < IOPRIO_BE_NR; i++) {
        if (! list_empty(&k2d->rt_reqs[i])) {
            return(true);
        }
    }
    return(false);
}

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

static latency_us_t k2_linear_interpolation(const u32 val
        , const u32 lower_val, const u32 upper_val
        , const latency_us_t lower_lat, const latency_us_t upper_lat)
{
    const u32 diff_val = upper_val - lower_val;
    const u32 diff_lat = upper_lat - lower_lat;
    const u32 offset_val = val - lower_val;
    const u32 value_percentage = 100 * offset_val / diff_val;
    return lower_lat + diff_lat * value_percentage / 100;

}

/**
 * @brief Determine the expected latency of a request
 */
static latency_us_t k2_expected_request_latency(struct k2_data* k2d, struct request* rq)
{
    const unsigned int rq_size = blk_rq_bytes(rq);
    //unsigned int rq_sectors = blk_rq_sectors(rq);

    // Requests that are neither write nor read are not taken into account
    latency_us_t rq_lat = 0;

    K2_LOG(printk(KERN_INFO "k2: Request size: %u (%uk)", rq_size, rq_size / 1024));

    switch (rq->cmd_flags & REQ_OP_MASK) {
        case REQ_OP_READ:
            K2_LOG(printk(KERN_INFO "k2: Request is read"));
            if(rq_size <= K2_512) {
                rq_lat = k2d->rr_512_lat;
            } else if (rq_size <= K2_32K) {
                rq_lat = k2_linear_interpolation(rq_size, K2_512, K2_32K, k2d->rr_512_lat, k2d->rr_32K_lat);
            } else if (rq_size < K2_2048K) {
                rq_lat = k2_linear_interpolation(rq_size, K2_32K, K2_2048K, k2d->rr_32K_lat, k2d->rr_2048K_lat);
            } else {
                rq_lat = k2d->rr_2048K_lat;
            }
            break;
        case REQ_OP_WRITE:
            K2_LOG(printk(KERN_INFO "k2: Request is write"));
            if(rq_size <= K2_512) {
                rq_lat = k2d->rw_512_lat;
            } else if (rq_size <= K2_32K) {
                rq_lat = k2_linear_interpolation(rq_size, K2_512, K2_32K, k2d->rw_512_lat, k2d->rw_32K_lat);
            } else if (rq_size < K2_2048K) {
                rq_lat = k2_linear_interpolation(rq_size, K2_32K, K2_2048K, k2d->rw_32K_lat, k2d->rw_2048K_lat);
            } else {
                rq_lat = k2d->rw_2048K_lat;
            }
            break;
        default:
            K2_LOG(printk(KERN_INFO "k2: Request is misc: %u", rq->cmd_flags & REQ_OP_MASK));
    }
    K2_LOG(printk(KERN_INFO "k2: Expected introduced latency: %u", rq_lat));
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
static inline void k2_set_rq_latency(struct request* rq, latency_us_t rq_lat)
{
    rq->elv.priv[0] = (void*)(unsigned long)rq_lat;
    rq->elv.priv[1] = (void*)(unsigned long)blk_rq_bytes(rq);
}

/**
 * @brief Get the estimated latency introduced by a certain request
 * @details For assigning additional data to each request, the kernel offers certain pointers in the request struct
 * Apply some magic casting and be done with it.
 * */
static inline latency_us_t k2_get_rq_latency(struct request* rq)
{
    return (uintptr_t)rq->elv.priv[0];
}

/**
 * @brief Add a request to the calculation of globally in-flight requests
 * @details This function has to be called from a locked context, as concurrent
 * accesses to the global struct would tamper with the result
 * @param k2d The global k2_data struct
 * @param rq The request to process
 */
static inline void k2_add_latency(struct k2_data* k2d, struct request* rq)
{
    unsigned int count = k2d->inflight + 1;
    latency_us_t lat = k2d->current_inflight_latency + k2_get_rq_latency(rq);

    assert_spin_locked(&k2d->lock);

    K2_LOG(printk(KERN_DEBUG "k2: Added: current inflight %u, current_latency %u", count, lat));

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
static inline void k2_remove_latency(struct k2_data* k2d, struct request* rq)
{
    unsigned int count;
    latency_us_t lat;

    assert_spin_locked(&k2d->lock);

    count = k2d->inflight;
    lat = k2d->current_inflight_latency;

    if (count >=1 ) {
        count--;
    }

    if (lat > k2_get_rq_latency(rq)) {
        lat -= k2_get_rq_latency(rq);
    } else {
        lat = 0;
    }

    K2_LOG(printk(KERN_DEBUG "k2: Removed: current inflight %u, current_latency %u", count, lat));

    k2d->inflight = count;
    k2d->current_inflight_latency = lat;
}

/**
 * @brief Update the lowest pending request time in the software queues
 * @details This function has to be called from a locked context, as concurrent
 * accesses to the global struct would tamper with the result
 * @param k2d The global k2_data structure
 */
static void k2_update_lowest_pending_latency(struct k2_data* k2d)
{
    unsigned int i;
    struct request* rq;
    latency_us_t lowest_lat = LATENCY_US_T_MAX;
    latency_us_t rq_lat;

    assert_spin_locked(&k2d->lock);

    // Realtime prio requests
    for (i = 0; i < IOPRIO_BE_NR; i++) {
        if (!list_empty(&k2d->rt_reqs[i])) {
            rq = list_first_entry(&k2d->rt_reqs[i], struct request, queuelist);
            rq_lat = k2_get_rq_latency(rq);
            if (rq_lat < lowest_lat) {
                lowest_lat = rq_lat;
            }
        }
    }

    // Non realtime requests
    if (!list_empty(&k2d->be_reqs)) {
        rq = list_first_entry(&k2d->be_reqs, struct request, queuelist);
        rq_lat = k2_get_rq_latency(rq);
        if (rq_lat < lowest_lat) {
            lowest_lat = rq_lat;
        }
    }
    k2d->lowest_upcoming_latency =  lowest_lat;
}

/**
 * @brief Determine, weather a request can currently be dispatched with respect to the scheduling limitations
 */
static inline bool k2_does_request_fit(struct k2_data* k2d, struct request* rq) {
    bool does_fit;

    // Do not deadlock when request time exceeds maximum inflight latency
    if (k2d->inflight == 0) {
        K2_LOG(printk(KERN_INFO "k2: Queue is empty, Request dispatch accepted!"));
        return true;
    }

    if (k2d->max_inflight_latency > k2d->current_inflight_latency) {
        does_fit = k2_get_rq_latency(rq) <= k2d->max_inflight_latency - k2d->current_inflight_latency;
    } else {
        // Queue limit already exceeded
        does_fit = false;
    }

    if (!does_fit) {
        K2_LOG(printk(KERN_INFO "k2: Request dispatch rejected, queue limit would be exceeded!"));
    } else {
        K2_LOG(printk(KERN_INFO "k2: Request dispatch accepted!"));
    }

    return does_fit;
}

static int k2_add_dynamic_rt_rq(struct k2_data* k2d, pid_t pid, latency_us_t interval) {
    struct k2_dynamic_rt_rq* rq;
    struct list_head* list_elem;
    unsigned long flags;
    int error = 0;

    // TODO: Avoid busy waiting here?
    spin_lock_irqsave(&k2d->lock, flags);

    // Check if PID is already assigned
    if(!list_empty(&k2d->rt_dynamic_rqs)) {
        list_for_each(list_elem, &k2d->rt_dynamic_rqs) {
            rq = list_entry(list_elem, struct k2_dynamic_rt_rq, list);
            if(rq->pid == pid) {
                error = -EEXIST;
                goto finally;
            }
        }
    }

    // TODO: Is this memory handling correct?
    rq = kzalloc_node(sizeof(struct k2_dynamic_rt_rq), GFP_KERNEL, k2d->rq->node);
    if (NULL == rq) {
        kobject_put(&k2d->rq->elevator->kobj);
        error = -ENOMEM;
        goto finally;
    }

    INIT_LIST_HEAD(&rq->list);
    INIT_LIST_HEAD(&rq->reqs);
    rq->pid = pid;
    rq->interval = interval;

    // Register this request queue
    list_add_tail(&rq->list, &k2d->rt_dynamic_rqs);

    finally:
    spin_unlock_irqrestore(&k2d->lock, flags);
    return error;
}

static int k2_del_dynamic_rt_rq(struct k2_data* k2d, pid_t pid) {
    struct k2_dynamic_rt_rq* rq;
    struct list_head* list_elem;
    struct list_head* tmp;
    int error = 0;
    unsigned long flags;

    // TODO: Avoid busy waiting here?
    spin_lock_irqsave(&k2d->lock, flags);

    // Check if PID is already assigned
    if(!list_empty(&k2d->rt_dynamic_rqs)) {
        list_for_each_safe(list_elem, tmp, &k2d->rt_dynamic_rqs) {
            rq = list_entry(list_elem, struct k2_dynamic_rt_rq, list);
            if (rq->pid == pid) {
                list_del(list_elem);
                kfree(rq);
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
 * @brief Get the k2_data structure active on a certain disk by name
 * @param disk_name The name of the disk as listed in e.g. /dev/nvme0n1, omit the /dev/ part
 * @return Pointer to the according k2_data if exists, else NULL
 */
static struct k2_data* k2_get_k2d_by_disk(const char* disk_name) {
    unsigned long flags;
    struct list_head* list_elem;
    struct k2_data* ret = NULL;
    struct k2_data* tmp;

    if (!k2_global_k2_dev) {
        return NULL;
    }

    spin_lock_irqsave(&k2_global_k2_dev->lock, flags);

    if (list_empty(&k2_global_k2_dev->k2_instances)) {
        goto finally;
    }
    list_for_each(list_elem, &k2_global_k2_dev->k2_instances) {
        // TODO: Lock here? Should not be required, as this value should not change.
        tmp = list_entry(list_elem, struct k2_data, global_k2_list_element);
        printk(KERN_INFO "k2: get k2d by name \"%s\", \"%s\"\n", disk_name, tmp->rq->disk->disk_name);
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
	struct k2_data        *k2d;
	struct elevator_queue *eq;
	unsigned i;

	eq = elevator_alloc(rq, et);
	if (eq == NULL)
		return(-ENOMEM);

	/* allocate scheduler data from mem pool of request queue */
	k2d = kzalloc_node(sizeof(struct k2_data), GFP_KERNEL, rq->node);
	if (k2d == NULL) {
		kobject_put(&eq->kobj);
		return(-ENOMEM);
	}
	eq->elevator_data = k2d;

	k2d->inflight     =  0;
    k2d->current_inflight_latency = 0;
    k2d->max_inflight_latency = K2_MAX_INFLIGHT_USECONDS;
    k2d->lowest_upcoming_latency = LATENCY_US_T_MAX;
	for (i = 0; i < IOPRIO_BE_NR; i++)
		INIT_LIST_HEAD(&k2d->rt_reqs[i]);

	INIT_LIST_HEAD(&k2d->be_reqs);

	k2d->sort_list[READ] = RB_ROOT;
	k2d->sort_list[WRITE] = RB_ROOT;

    k2d->rr_512_lat = K2_RR_512_LAT;
    k2d->rr_32K_lat = K2_RR_32K_LAT;
    k2d->rr_2048K_lat = K2_RR_2048K_LAT;

    k2d->rw_512_lat = K2_RW_512_LAT;
    k2d->rw_32K_lat = K2_RW_32K_LAT;
    k2d->rw_2048K_lat = K2_RW_2048K_LAT;

    INIT_LIST_HEAD(&k2d->global_k2_list_element);

	spin_lock_init(&k2d->lock);

	rq->elevator = eq;

    k2d->rq = rq;

    INIT_LIST_HEAD(&k2d->rt_dynamic_rqs);

    // Register this instance so it can be addressed from ioctl
    if(k2_global_k2_dev) {
        list_add_tail(&k2d->global_k2_list_element, &k2_global_k2_dev->k2_instances);
    } else {
        printk(KERN_WARNING "Could not register k2 scheduler instance for device /dev/%s for ioctl interaction", k2d->rq->disk->disk_name);
    }

	printk(KERN_INFO "k2: I/O scheduler set up for %s\n", rq->disk->disk_name);
	return(0);
}

static void k2_exit_sched(struct elevator_queue *eq)
{
	struct k2_data *k2d = eq->elevator_data;
    char* blk_name = k2d->rq->disk->disk_name;
    struct list_head* list_elem;
    struct list_head* tmp;
    struct k2_dynamic_rt_rq* rt_rqs;

    // Delete from global dev node
    if (k2_global_k2_dev) {
        list_del(&k2d->global_k2_list_element);
    }

    // Clean all dynamically allocated request queues
    if (!list_empty(&k2d->rt_dynamic_rqs)) {
        list_for_each_safe(list_elem, tmp, &k2d->rt_dynamic_rqs) {
            rt_rqs = list_entry(list_elem, struct k2_dynamic_rt_rq, list);
            // TODO: How to handle requests still in software queues?
            //  Do nothing like in static queues? Are those lost?
            //  What about the associated kernel memory buffer?
            printk("k2: Deleting realtime request queue for pid %d on %s", rt_rqs->pid, k2d->rq->disk->disk_name);
            kfree(rt_rqs);
        }
    }

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

	return(has_work);
}

/* Inserts a request into the scheduler queue. For now, at_head is ignored! */
static void k2_insert_requests(struct blk_mq_hw_ctx *hctx, struct list_head *rqs,
				bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
	unsigned long flags;
    latency_us_t rq_lat;

	spin_lock_irqsave(&k2d->lock, flags);
	while (!list_empty(rqs)) {
		struct request *r;
		int    prio_class;
		int    prio_value;

		r = list_first_entry(rqs, struct request, queuelist);
		list_del_init(&r->queuelist);

		/* if task has no io prio, derive it from its nice value */
		if (ioprio_valid(r->ioprio)) {
			prio_class = IOPRIO_PRIO_CLASS(r->ioprio);
			prio_value = IOPRIO_PRIO_VALUE(prio_class, r->ioprio);
		} else {
			k2_ioprio_from_task(&prio_class, &prio_value);
		}

		k2_add_rq_rb(k2d, r);
		if (rq_mergeable(r)) {
			elv_rqhash_add(q, r);
			if (!q->last_merge)
				q->last_merge = r;
		}

        rq_lat = k2_expected_request_latency(k2d, r);
        k2_set_rq_latency(r, rq_lat);

		if (prio_class == IOPRIO_CLASS_RT) {
			if (prio_value >= IOPRIO_BE_NR || prio_value < 0)
				prio_value = IOPRIO_NORM;

			list_add_tail(&r->queuelist, &k2d->rt_reqs[prio_value]);
		} else {
			list_add_tail(&r->queuelist, &k2d->be_reqs);
		}

        // TODO: Inline this functionality to the iterations already done in this function
        k2_update_lowest_pending_latency(k2d);
	}
	spin_unlock_irqrestore(&k2d->lock, flags);
}

static struct request *k2_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct k2_data *k2d = hctx->queue->elevator->elevator_data;
    struct request *rq;
	unsigned long flags;
	unsigned int  i;

	spin_lock_irqsave(&k2d->lock, flags);

	/* inflight counter may have changed since last call to has_work */
	if (k2d->current_inflight_latency >= k2d->max_inflight_latency)
		goto abort;

	/* always prefer real-time requests */
	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (!list_empty(&k2d->rt_reqs[i])) {
            rq = list_first_entry(&k2d->rt_reqs[i], struct request, queuelist);
            if (k2_does_request_fit(k2d, rq)) {
                goto end;
            }

		}
	}

	/* no rt rqs waiting: choose other workload */
	if (!list_empty(&k2d->be_reqs)) {
        rq = list_first_entry(&k2d->be_reqs, struct request, queuelist);
        if (k2_does_request_fit(k2d, rq)) {
            goto end;
        }
	}

    goto abort;

abort:
	/* both request lists are empty or inflight counter is too high */
	spin_unlock_irqrestore(&k2d->lock, flags);

	return(NULL);

end:
	k2_remove_request(q, rq);
    k2_add_latency(k2d, rq);
    rq->rq_flags |= RQF_STARTED;
    // TODO: Inline this functionality to the iterations already done in this function
    k2_update_lowest_pending_latency(k2d);

	spin_unlock_irqrestore(&k2d->lock, flags);

	return(rq);
}

static bool k2_bio_merge(struct request_queue *q, struct bio *bio, unsigned int watdis)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *free = NULL;
	unsigned long flags;
	bool ret;

    K2_LOG(printk(KERN_INFO "k2: Entering k2_bio_merge"));

	spin_lock_irqsave(&k2d->lock, flags);
	ret = blk_mq_sched_try_merge(q, bio, &free);
	spin_unlock_irqrestore(&k2d->lock, flags);

	if (free)
		blk_mq_free_request(free);

	return(ret);
}

static int k2_request_merge(struct request_queue *q, struct request **rq,
				struct bio *bio)
{
	struct k2_data *k2d = q->elevator->elevator_data;
	struct request *__rq;
	sector_t sector = bio_end_sector(bio);

    K2_LOG(printk(KERN_INFO "k2: Entering k2_request_merge"));
	assert_spin_locked(&k2d->lock);

	// should request merging cross I/O prios?

	__rq = elv_rb_find(&k2d->sort_list[bio_data_dir(bio)], sector);
	if (__rq) {
		BUG_ON(sector != blk_rq_pos(__rq));

		if (elv_bio_merge_ok(__rq, bio)) {
			*rq = __rq;
			return(ELEVATOR_FRONT_MERGE);
		}
	}

	return(ELEVATOR_NO_MERGE);
}

static void k2_request_merged(struct request_queue *q, struct request *rq,
				enum elv_merge type)
{
	struct k2_data *k2d = q->elevator->elevator_data;

    K2_LOG(printk(KERN_INFO "k2: Entering k2_request_merged"));

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	if (type == ELEVATOR_FRONT_MERGE) {
		k2_del_rq_rb(k2d, rq);
		k2_add_rq_rb(k2d, rq);
	}
}

/*
 * This function is called to notify the scheduler that the requests
 * rq and 'next' have been merged, with 'next' going away.
 */
static void k2_requests_merged(struct request_queue *q, struct request *rq,
				struct request *next)
{
    struct k2_data *k2d = rq->q->elevator->elevator_data;
    unsigned long flags;

    K2_LOG(printk(KERN_INFO "k2: Entering k2_requests_merged"));


    spin_lock_irqsave(&k2d->lock, flags);
    // TODO: How to handle inflight latency here? Is it necessary?

	k2_remove_request(q, next);
    k2_set_rq_latency(rq, k2_expected_request_latency(k2d, rq));
    k2_update_lowest_pending_latency(k2d);

    spin_unlock_irqrestore(&k2d->lock, flags);
}

static void k2_completed_request(struct request *rq, u64 watDis)
{
    struct k2_data *k2d = rq->q->elevator->elevator_data;
    unsigned long flags;
    latency_us_t current_lat;
    latency_us_t max_lat;
    latency_us_t lowest_upcoming_lat;
    u64 real_latency = ktime_get_ns() - rq->io_start_time_ns;

    trace_k2_completed_request(rq, real_latency);

    spin_lock_irqsave(&k2d->lock, flags);

    k2_remove_latency(k2d, rq);

    /*
     * Read both counters here to avoid stall situation if max_inflight
     * is modified simultaneously.
     */
    current_lat = k2d->current_inflight_latency;
    max_lat = k2d->max_inflight_latency;
    lowest_upcoming_lat = k2d->lowest_upcoming_latency;



    spin_unlock_irqrestore(&k2d->lock, flags);

    /*
    * This completion call creates leeway for dispatching new requests.
    * Rerunning the hw queues have to be done manually since we throttle
    * request dispatching. Mind that this has to be executed in async mode.
    */
    if (current_lat < max_lat && max_lat - current_lat >= lowest_upcoming_lat) {
        blk_mq_run_hw_queues(rq->q, true);
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

        .bio_merge         = k2_bio_merge,
		.request_merge     = k2_request_merge,
		.request_merged    = k2_request_merged,
		.requests_merged   = k2_requests_merged,
	},
	.elevator_attrs = k2_attrs,
	.elevator_name  = "k2",
	.elevator_owner = THIS_MODULE,
};


/* =============================
 * ==== MODULE REGISTRATION ====
 * ========================== */

static int __init k2_init(void) {
    int error = 0;
    printk(KERN_INFO "k2: Loading K2 I/O scheduler.\n");
    error = k2_init_dev();
    if (error) {
        return error;
    }
    return elv_register(&k2_iosched);
}

static void __exit k2_exit(void) {
    printk(KERN_INFO "k2: Unloading K2 I/O scheduler.\n");
    elv_unregister(&k2_iosched);
    k2_close_dev(k2_global_k2_dev);
}

module_init(k2_init);
module_exit(k2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Till Miemietz, Georg Grassnick");
MODULE_DESCRIPTION("A work-constraining I/O scheduler with real-time notion.");
MODULE_VERSION("0.1");
