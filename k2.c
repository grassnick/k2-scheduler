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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/ioprio.h>
#include <linux/limits.h>

/** Macro to disable Kernel massages meant for debugging */
#define K2_LOG(log) log

/** A type that represents the latency of a request in us */
typedef u32 latency_us_t;
#define LATENCY_US_T_MAX U32_MAX

/** The initial value for the maximum in-flight latency */
#define K2_MAX_INFLIGHT_USECONDS 10000000

#define K2_RR_4K_LAT   54365
#define K2_RR_8K_LAT   64170
#define K2_RR_16K_LAT  56925
#define K2_RR_64K_LAT  93675
#define K2_RR_512K_LAT 241110

#define K2_RW_4K_LAT   56890
#define K2_RW_8K_LAT   76225
#define K2_RW_16K_LAT  76715
#define K2_RW_64K_LAT  82640
#define K2_RW_512K_LAT 239385

#define K2_4K 4 << 10
#define K2_64K 64 << 10
#define K2_512K 512 << 10


extern bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
		struct request **merged_request);

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
    latency_us_t rr_4K_lat;
    latency_us_t rr_8K_lat;
    latency_us_t rr_16K_lat;
    latency_us_t rr_64K_lat;
    latency_us_t rr_512K_lat;

    /* Random Write */
    latency_us_t rw_4K_lat;
    latency_us_t rw_8K_lat;
    latency_us_t rw_16K_lat;
    latency_us_t rw_64K_lat;
    latency_us_t rw_512K_lat;

	/* further group real-time requests by I/O priority */
	struct list_head rt_reqs[IOPRIO_BE_NR];
	struct list_head be_reqs;

	/* Sector-ordered lists for request merging */
	struct rb_root sort_list[2];

	spinlock_t lock;
};

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
    __ATTR_NULL
};


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

    if (k2d->max_inflight_latency - k2d->current_inflight_latency < k2d->lowest_upcoming_latency) {
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

/**
 * @brief Determine the expected latency of a request
 */
static latency_us_t k2_expected_request_latency(struct k2_data* k2d, struct request* rq)
{
    // For now: assume behaviour that mimics the legacy k2-8 behaviour
    unsigned int rq_size = blk_rq_bytes(rq);
    latency_us_t rq_lat = 0;
    K2_LOG(printk(KERN_INFO "k2: Request size: %u", rq_size));
    //unsigned int rq_sectors = blk_rq_sectors(rq);

    switch (rq->cmd_flags & REQ_OP_MASK) {
        case REQ_OP_READ:
            K2_LOG(printk(KERN_INFO "k2: Request is read"));
            if(rq_size == K2_4K) {
                rq_lat = k2d->rr_4K_lat;
            } else if (rq_size == K2_64K) {
                rq_lat = k2d->rr_64K_lat;
            }
            break;
        case REQ_OP_WRITE:
            K2_LOG(printk(KERN_INFO "k2: Request is write"));
            if(rq_size == K2_4K) {
                rq_lat = k2d->rw_4K_lat;
            } else if (rq_size == K2_64K) {
                rq_lat = k2d->rw_64K_lat;
            }
            break;
        default:
            K2_LOG(printk(KERN_INFO "k2: Request is misc: %u", rq->cmd_flags & REQ_OP_MASK));
    }
    K2_LOG(printk(KERN_INFO "k2: Expected introduced latency: %u", rq_lat));
    return rq_lat;

    legacy:
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
static inline bool k2_does_request_fit(struct k2_data* k2d, struct request* rq)
{
    if (k2d->max_inflight_latency > k2d->current_inflight_latency) {
        return k2_get_rq_latency(rq) <= k2d->max_inflight_latency - k2d->current_inflight_latency;
    }
    return false;
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

    k2d->rr_4K_lat = K2_RR_4K_LAT;
    k2d->rr_8K_lat = K2_RR_8K_LAT;
    k2d->rr_16K_lat = K2_RR_16K_LAT;
    k2d->rr_64K_lat = K2_RR_64K_LAT;
    k2d->rr_512K_lat = K2_RR_512K_LAT;

    k2d->rw_4K_lat = K2_RW_4K_LAT;
    k2d->rw_8K_lat = K2_RW_8K_LAT;
    k2d->rw_16K_lat = K2_RW_16K_LAT;
    k2d->rw_64K_lat = K2_RW_64K_LAT;
    k2d->rw_512K_lat = K2_RW_512K_LAT;

	spin_lock_init(&k2d->lock);

	rq->elevator = eq;
	printk(KERN_INFO "k2: I/O scheduler set up.\n");
	return(0);
}

static void k2_exit_sched(struct elevator_queue *eq)
{
	struct k2_data *k2d = eq->elevator_data;

	kfree(k2d);
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

static int __init k2_init(void)
{
	printk(KERN_INFO "k2: Loading K2 I/O scheduler.\n");
	return(elv_register(&k2_iosched));
}

static void __exit k2_exit(void)
{
	printk(KERN_INFO "k2: Unloading K2 I/O scheduler.\n");
	elv_unregister(&k2_iosched);
}

module_init(k2_init);
module_exit(k2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Till Miemietz, Georg Grassnick");
MODULE_DESCRIPTION("A work-constraining I/O scheduler with real-time notion.");
MODULE_VERSION("0.1");
