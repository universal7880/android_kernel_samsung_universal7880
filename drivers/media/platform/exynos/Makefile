obj-$(CONFIG_EXYNOS_MEDIA_DEVICE)	+= mdev/
obj-$(CONFIG_VIDEO_EXYNOS_SCALER)	+= scaler/
obj-$(CONFIG_VIDEO_EXYNOS_MFC)		+= mfc/
obj-$(CONFIG_VIDEO_EXYNOS_HEVC)		+= hevc/
obj-$(CONFIG_VIDEO_EXYNOS_FIMG2D_V5)	+= fimg2d_v5/
obj-$(CONFIG_VIDEO_EXYNOS_SMFC)		+= smfc/
ifeq ($(CONFIG_SOC_EXYNOS7880),y)
obj-$(CONFIG_VIDEO_EXYNOS_FIMC_IS2)	+= fimc-is2-7880/
else
obj-$(CONFIG_VIDEO_EXYNOS_FIMC_IS2)	+= fimc-is2/
endif
EXTRA_CLAGS += -Idrivers/media/video
