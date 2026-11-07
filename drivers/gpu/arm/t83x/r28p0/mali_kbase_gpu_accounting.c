/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <mali_kbase.h>
#include <mali_kbase_gpu_accounting.h>

#define CREATE_TRACE_POINTS
#include "mali_kbase_gpu_mem_trace.h"
#include "mali_kbase_gpu_work_trace.h"
#undef CREATE_TRACE_POINTS

#define GPU_WORK_SAMPLE_NS (NSEC_PER_SEC / 4)

struct kbase_gpu_process {
	struct list_head link;
	pid_t tgid;
	unsigned int contexts;
	long pages;
};

struct kbase_gpu_uid {
	struct list_head link;
	u32 uid;
	unsigned int contexts;
	u64 start_ns;
	u64 active_ns;
};

/* hwaccess_lock serializes slot changes, timer samples and UID lifetimes. */
static void account_work(struct kbase_device *kbdev, u64 now)
{
	u64 elapsed = now - kbdev->gpu_work_last_ns;
	int slot;

	for (slot = 0; slot < kbdev->gpu_props.num_job_slots; slot++) {
		struct kbase_gpu_uid *owner = kbdev->gpu_work_slots[slot];
		int earlier;

		if (!owner)
			continue;

		/* A UID can be executing on several slots at the same time. */
		for (earlier = 0; earlier < slot; earlier++)
			if (kbdev->gpu_work_slots[earlier] == owner)
				break;
		if (earlier == slot && elapsed) {
			if (!owner->active_ns)
				owner->start_ns = kbdev->gpu_work_last_ns;
			owner->active_ns += elapsed;
		}
	}
	kbdev->gpu_work_last_ns = now;
}

static void report_work(struct kbase_gpu_uid *owner, u64 now)
{
	if (owner->active_ns && now - owner->start_ns <= NSEC_PER_SEC)
		trace_gpu_work_period(0, owner->uid, owner->start_ns,
				      now, owner->active_ns);
	owner->active_ns = 0;
}

static enum hrtimer_restart sample_gpu_work(struct hrtimer *timer)
{
	struct kbase_device *kbdev = container_of(timer, struct kbase_device,
						 gpu_work_timer);
	struct kbase_gpu_uid *owner;
	unsigned long flags;
	bool active = false;
	u64 now;
	int slot;

	spin_lock_irqsave(&kbdev->hwaccess_lock, flags);
	now = ktime_get_raw_ns();
	account_work(kbdev, now);
	list_for_each_entry(owner, &kbdev->gpu_uids, link)
		report_work(owner, now);
	if (trace_gpu_work_period_enabled())
		for (slot = 0; slot < kbdev->gpu_props.num_job_slots; slot++)
			active |= kbdev->gpu_work_slots[slot] != NULL;
	kbdev->gpu_work_sampling = active;
	if (active)
		hrtimer_forward_now(timer, ns_to_ktime(GPU_WORK_SAMPLE_NS));
	spin_unlock_irqrestore(&kbdev->hwaccess_lock, flags);

	return active ? HRTIMER_RESTART : HRTIMER_NORESTART;
}

void kbase_gpu_work_switch(struct kbase_device *kbdev, int slot,
			   const struct kbase_jd_atom *atom)
{
	struct kbase_gpu_uid *owner = NULL;
	u64 now;

	lockdep_assert_held(&kbdev->hwaccess_lock);
	if (atom && !kbase_jd_katom_is_protected(atom))
		owner = atom->kctx->gpu_uid;

	if (owner == kbdev->gpu_work_slots[slot])
		return;

	if (kbdev->gpu_work_sampling)
		account_work(kbdev, ktime_get_raw_ns());
	kbdev->gpu_work_slots[slot] = owner;

	if (owner && !kbdev->gpu_work_sampling &&
	    trace_gpu_work_period_enabled()) {
		now = ktime_get_raw_ns();
		kbdev->gpu_work_last_ns = now;
		kbdev->gpu_work_sampling = true;
		hrtimer_start(&kbdev->gpu_work_timer,
			      ns_to_ktime(GPU_WORK_SAMPLE_NS), HRTIMER_MODE_REL);
	}
}

void kbase_gpu_accounting_init(struct kbase_device *kbdev)
{
	spin_lock_init(&kbdev->gpu_mem_lock);
	INIT_LIST_HEAD(&kbdev->gpu_processes);
	INIT_LIST_HEAD(&kbdev->gpu_uids);
	hrtimer_init(&kbdev->gpu_work_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	kbdev->gpu_work_timer.function = sample_gpu_work;
}

void kbase_gpu_accounting_term(struct kbase_device *kbdev)
{
	hrtimer_cancel(&kbdev->gpu_work_timer);
}

void kbase_gpu_accounting_context_init(struct kbase_context *kctx)
{
	struct kbase_device *kbdev = kctx->kbdev;
	struct kbase_gpu_process *new_process, *process;
	struct kbase_gpu_uid *new_owner, *owner;
	u32 uid = from_kuid_munged(&init_user_ns, current_uid());
	unsigned long flags;

	new_process = kzalloc(sizeof(*new_process), GFP_KERNEL);
	spin_lock_irqsave(&kbdev->gpu_mem_lock, flags);
	list_for_each_entry(process, &kbdev->gpu_processes, link) {
		if (process->tgid == kctx->tgid) {
			kctx->gpu_process = process;
			break;
		}
	}
	if (!kctx->gpu_process && new_process) {
		new_process->tgid = kctx->tgid;
		list_add(&new_process->link, &kbdev->gpu_processes);
		kctx->gpu_process = new_process;
		new_process = NULL;
	}
	if (kctx->gpu_process)
		kctx->gpu_process->contexts++;
	spin_unlock_irqrestore(&kbdev->gpu_mem_lock, flags);
	kfree(new_process);

	new_owner = kzalloc(sizeof(*new_owner), GFP_KERNEL);
	spin_lock_irqsave(&kbdev->hwaccess_lock, flags);
	list_for_each_entry(owner, &kbdev->gpu_uids, link) {
		if (owner->uid == uid) {
			kctx->gpu_uid = owner;
			break;
		}
	}
	if (!kctx->gpu_uid && new_owner) {
		new_owner->uid = uid;
		list_add(&new_owner->link, &kbdev->gpu_uids);
		kctx->gpu_uid = new_owner;
		new_owner = NULL;
	}
	if (kctx->gpu_uid)
		kctx->gpu_uid->contexts++;
	spin_unlock_irqrestore(&kbdev->hwaccess_lock, flags);
	kfree(new_owner);
}

void kbase_gpu_accounting_context_term(struct kbase_context *kctx)
{
	struct kbase_device *kbdev = kctx->kbdev;
	struct kbase_gpu_process *process = kctx->gpu_process;
	struct kbase_gpu_uid *owner = kctx->gpu_uid;
	unsigned long flags;
	int slot;

	spin_lock_irqsave(&kbdev->gpu_mem_lock, flags);
	if (process && !--process->contexts) {
		list_del(&process->link);
		trace_gpu_mem_total(0, process->tgid, 0);
	} else {
		process = NULL;
	}
	spin_unlock_irqrestore(&kbdev->gpu_mem_lock, flags);
	kfree(process);

	spin_lock_irqsave(&kbdev->hwaccess_lock, flags);
	if (owner && !--owner->contexts) {
		u64 now = ktime_get_raw_ns();

		if (kbdev->gpu_work_sampling)
			account_work(kbdev, now);
		for (slot = 0; slot < kbdev->gpu_props.num_job_slots; slot++) {
			if (WARN_ON_ONCE(kbdev->gpu_work_slots[slot] == owner))
				kbdev->gpu_work_slots[slot] = NULL;
		}
		report_work(owner, now);
		list_del(&owner->link);
	} else {
		owner = NULL;
	}
	spin_unlock_irqrestore(&kbdev->hwaccess_lock, flags);
	kfree(owner);
}

static void report_memory(struct kbase_device *kbdev, struct kbase_context *kctx,
			  long pages)
{
	struct kbase_gpu_process *process = kctx ? kctx->gpu_process : NULL;

	kbdev->gpu_accounted_pages += pages;
	trace_gpu_mem_total(0, 0,
			    (u64)max(0L, kbdev->gpu_accounted_pages) << PAGE_SHIFT);
	if (process) {
		process->pages += pages;
		trace_gpu_mem_total(0, process->tgid,
				    (u64)max(0L, process->pages) << PAGE_SHIFT);
	}
}

u32 kbase_gpu_account_pages(struct kbase_device *kbdev,
			    struct kbase_context *kctx, long pages)
{
	unsigned long flags;
	u32 count = 0;

	spin_lock_irqsave(&kbdev->gpu_mem_lock, flags);
	if (pages < 0) {
		if (kctx)
			count = kbase_atomic_sub_pages(-pages, &kctx->used_pages);
		kbase_atomic_sub_pages(-pages, &kbdev->memdev.used_pages);
	} else {
		if (kctx)
			count = kbase_atomic_add_pages(pages, &kctx->used_pages);
		kbase_atomic_add_pages(pages, &kbdev->memdev.used_pages);
	}
	report_memory(kbdev, kctx, pages);
	spin_unlock_irqrestore(&kbdev->gpu_mem_lock, flags);
	return count;
}

void kbase_gpu_account_import(struct kbase_context *kctx, long pages)
{
	struct kbase_device *kbdev = kctx->kbdev;
	unsigned long flags;

	if (!pages)
		return;

	spin_lock_irqsave(&kbdev->gpu_mem_lock, flags);
	report_memory(kbdev, kctx, pages);
	spin_unlock_irqrestore(&kbdev->gpu_mem_lock, flags);
}
