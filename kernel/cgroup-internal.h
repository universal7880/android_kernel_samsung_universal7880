/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CGROUP_INTERNAL_H
#define _CGROUP_INTERNAL_H

extern struct mutex cgroup_mutex;
extern spinlock_t css_set_lock;

int __cgroup_task_count(const struct cgroup *cgrp);
void cgroup_notify_frozen(struct cgroup *cgrp);

static inline bool cgroup_is_dead(const struct cgroup *cgrp)
{
	return !(cgrp->self.flags & CSS_ONLINE);
}

#endif
