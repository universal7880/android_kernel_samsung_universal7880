/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM power

#if !defined(_MALI_GPU_WORK_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _MALI_GPU_WORK_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(gpu_work_period,
	TP_PROTO(u32 gpu_id, u32 uid, u64 start_time_ns, u64 end_time_ns,
		 u64 total_active_duration_ns),
	TP_ARGS(gpu_id, uid, start_time_ns, end_time_ns, total_active_duration_ns),
	TP_STRUCT__entry(
		__field(u32, gpu_id)
		__field(u32, uid)
		__field(u64, start_time_ns)
		__field(u64, end_time_ns)
		__field(u64, total_active_duration_ns)
	),
	TP_fast_assign(
		__entry->gpu_id = gpu_id;
		__entry->uid = uid;
		__entry->start_time_ns = start_time_ns;
		__entry->end_time_ns = end_time_ns;
		__entry->total_active_duration_ns = total_active_duration_ns;
	),
	TP_printk("gpu_id=%u uid=%u start_time_ns=%llu end_time_ns=%llu total_active_duration_ns=%llu",
		  __entry->gpu_id, __entry->uid, __entry->start_time_ns,
		  __entry->end_time_ns, __entry->total_active_duration_ns)
);
#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mali_kbase_gpu_work_trace
#include <trace/define_trace.h>
