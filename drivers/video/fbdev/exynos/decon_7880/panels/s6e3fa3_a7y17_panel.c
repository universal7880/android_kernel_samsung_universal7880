/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/notifier.h>

#include "s6e3fa3_panel.h"
#include "s6e3fa3_a7y17_param.h"
#ifdef CONFIG_EXYNOS_DECON_MDNIE_LITE
#include "mdnie.h"
#include "mdnie_lite_table_a7y17.h"
#endif

const struct s6e3fa3_panel_data s6e3fa3_a7y17_panel = {
	.model = "AMS568MW",
	.m_gray = m_gray,
	.offset_color = offset_color,
	.elvss = elvss_mpscon_offset_data,
	.aor = AOR_TABLE,
	.hlpm_60 = { SEQ_SELECT_HLPM_60, ARRAY_SIZE(SEQ_SELECT_HLPM_60) },
	.hlpm_02 = { SEQ_SELECT_HLPM_02, ARRAY_SIZE(SEQ_SELECT_HLPM_02) },
	.alpm_60 = { SEQ_SELECT_ALPM_60, ARRAY_SIZE(SEQ_SELECT_ALPM_60) },
	.alpm_02 = { SEQ_SELECT_ALPM_02, ARRAY_SIZE(SEQ_SELECT_ALPM_02) },
#ifdef CONFIG_EXYNOS_DECON_MDNIE_LITE
	.mdnie = &tune_info,
#endif
};
