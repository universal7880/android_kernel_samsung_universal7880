/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MALI_KBASE_GPU_ACCOUNTING_H
#define _MALI_KBASE_GPU_ACCOUNTING_H

struct kbase_context;
struct kbase_device;
struct kbase_jd_atom;

void kbase_gpu_accounting_init(struct kbase_device *kbdev);
void kbase_gpu_accounting_term(struct kbase_device *kbdev);
void kbase_gpu_accounting_context_init(struct kbase_context *kctx);
void kbase_gpu_accounting_context_term(struct kbase_context *kctx);
u32 kbase_gpu_account_pages(struct kbase_device *kbdev,
			    struct kbase_context *kctx, long pages);
void kbase_gpu_account_import(struct kbase_context *kctx, long pages);
void kbase_gpu_work_switch(struct kbase_device *kbdev, int slot,
			   const struct kbase_jd_atom *atom);

#endif
