# SPDX-License-Identifier: GPL-2.0
ifeq ($(CONFIG_SOC_EXYNOS7870),y)
dtb-y += exynos7870-a6lte_eur_open_00.dtb
dtb-y += exynos7870-a6lte_eur_open_01.dtb
dtb-y += exynos7870-a6lte_eur_open_02.dtb
dtb-y += exynos7870-a6lte_eur_open_03.dtb
endif

ifeq ($(CONFIG_SOC_EXYNOS7880),y)
dtb-y += exynos7880-a5y17lte_eur_open_00.dtb
dtb-y += exynos7880-a5y17lte_eur_open_01.dtb
dtb-y += exynos7880-a5y17lte_eur_open_02.dtb
dtb-y += exynos7880-a5y17lte_eur_open_03.dtb
dtb-y += exynos7880-a5y17lte_eur_open_05.dtb
dtb-y += exynos7880-a5y17lte_eur_open_07.dtb
dtb-y += exynos7880-a5y17lte_eur_open_08.dtb
dtb-y += exynos7880-a7y17lte_eur_open_00.dtb
dtb-y += exynos7880-a7y17lte_eur_open_01.dtb
dtb-y += exynos7880-a7y17lte_eur_open_02.dtb
dtb-y += exynos7880-a7y17lte_eur_open_03.dtb
dtb-y += exynos7880-a7y17lte_eur_open_04.dtb
dtb-y += exynos7880-a7y17lte_eur_open_06.dtb
endif

targets += dtbs
DTB_LIST  := $(dtb-y) $(dtbo-y)
always    := $(DTB_LIST)

dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files := *.dtb*
