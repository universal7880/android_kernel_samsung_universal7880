/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EXYNOS7880_DT_H
#define __EXYNOS7880_DT_H

#include <linux/init.h>

struct exynos7880_dt_board {
	const char *model;
	char variant;
	unsigned int revision;
};

#ifdef CONFIG_EXYNOS7880_BOARD_DTBS
int __init exynos7880_dt_validate(const void *dt, unsigned long size);
int __init exynos7880_dt_compose(const void *input, unsigned long input_size,
				 const void *bootstrap, const void *selected,
				 void *out, unsigned int out_size);
int __init exynos7880_dt_select(const void *catalogue, unsigned long size,
				const struct exynos7880_dt_board *board,
				const void **bootstrap, const void **selected);
#endif

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
