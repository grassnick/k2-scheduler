/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM k2

#if !defined(_TRACE_K2_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_K2_H

#include <linux/blkdev.h>
#include <linux/tracepoint.h>

TRACE_EVENT(k2_completed_request,

        TP_PROTO(struct request* rq, u64 real_latency),

        TP_ARGS(rq, real_latency),

        TP_STRUCT__entry(
            __field(u32, request_size)
            __field(u32, estimated_latency)
            __field(u64, real_latency)
        ),

        TP_fast_assign(
            // Request size is decremented once processing has progressed and is no longer valid when checked at request completion
            //__entry->request_size = blk_rq_bytes(rq);
            __entry->__entry->request_size = (uintptr_t)rq->elv.priv[1];
            __entry->estimated_latency = (uintptr_t)rq->elv.priv[0];
            __entry->real_latency = real_latency;
        ),

        TP_printk("%u,%u,%llu",
            __entry->request_size,
            __entry->estimated_latency,
            __entry->real_latency
        )
);

#endif /* _TRACE_K2_H */

/* This part must be outside protection */
/*#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE k2*/
#include <trace/define_trace.h>
