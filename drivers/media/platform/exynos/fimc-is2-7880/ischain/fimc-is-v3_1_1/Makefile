obj-$(CONFIG_FIMC_IS_7880_V3_1_1) += fimc-is-hw-pwr.o
obj-$(CONFIG_FIMC_IS_7880_V3_1_1) += fimc-is-hw-chain.o
ifeq ($(CONFIG_PM_DEVFREQ),y)
obj-$(CONFIG_FIMC_IS_7880_V3_1_1) += fimc-is-hw-dvfs.o
endif

EXTRA_CFLAGS += -Idrivers/media/platform/exynos/fimc-is2-7880
EXTRA_CFLAGS += -Idrivers/media/platform/exynos/fimc-is2-7880/include
