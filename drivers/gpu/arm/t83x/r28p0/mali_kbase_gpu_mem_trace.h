/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM gpu_mem

#if !defined(_MALI_GPU_MEM_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _MALI_GPU_MEM_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(gpu_mem_total,
	TP_PROTO(u32 gpu_id, u32 pid, u64 size),
	TP_ARGS(gpu_id, pid, size),
	TP_STRUCT__entry(
		__field(u32, gpu_id)
		__field(u32, pid)
		__field(u64, size)
	),
	TP_fast_assign(
		__entry->gpu_id = gpu_id;
		__entry->pid = pid;
		__entry->size = size;
	),
	TP_printk("gpu_id=%u pid=%u size=%llu", __entry->gpu_id,
		  __entry->pid, __entry->size)
);
#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mali_kbase_gpu_mem_trace
#include <trace/define_trace.h>
