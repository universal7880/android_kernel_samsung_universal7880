/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXYNOS7880_DT_H
#define __EXYNOS7880_DT_H

#include <linux/init.h>

struct exynos7880_dt_board {
	const char *model;
	char variant;
	unsigned int revision;
};

#ifdef CONFIG_SOC_EXYNOS7880
int __init exynos7880_dt_identify(const void *fdt,
				struct exynos7880_dt_board *board);
#else
static inline int exynos7880_dt_identify(const void *fdt,
				       struct exynos7880_dt_board *board)
{
	return 0;
}
#endif

#endif
