obj-$(CONFIG_EXYNOS_FIMC_IS) += setup-fimc-is.o
obj-$(CONFIG_EXYNOS_FIMC_IS) += setup-fimc-is-sensor.o
obj-$(CONFIG_EXYNOS_FIMC_IS) += setup-fimc-is-module.o
obj-$(CONFIG_EXYNOS_FIMC_IS) += setup-fimc-is-preprocessor.o

obj-$(CONFIG_EXYNOS_FIMC_IS) += fimc-is-v4_3_0/
obj-$(CONFIG_EXYNOS_FIMC_IS) += fimc-is-v4_0_0/
obj-$(CONFIG_EXYNOS_FIMC_IS) += fimc-is-v3_1_1/
obj-$(CONFIG_EXYNOS_FIMC_IS) += fimc-is-v3_11_0/
ifeq ($(CONFIG_SOC_EXYNOS7880),y)
obj-$(CONFIG_EXYNOS_FIMC_IS) += fimc-is-v5_10_0-7880/
else
obj-$(CONFIG_EXYNOS_FIMC_IS) += fimc-is-v5_10_0/
endif

EXTRA_CFLAGS += -Idrivers/media/platform/exynos/fimc-is2/include
